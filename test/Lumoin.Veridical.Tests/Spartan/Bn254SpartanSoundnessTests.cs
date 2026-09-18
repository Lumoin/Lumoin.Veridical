using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Soundness and failure-path coverage for BN254: an unsatisfying witness is
/// rejected at prove time (base and masked provers), and a valid proof with a
/// single flipped byte is rejected by the verifier. The BN254 counterparts of
/// the BLS <see cref="SpartanFailureTests"/> / <see cref="MaskedSpartanSoundnessTests"/>
/// legs, confirming that the prove/verify path is generic in the curve's
/// scalar and group arithmetic: the soundness contract holds over BN254 just
/// as it does over BLS12-381.
/// </summary>
[TestClass]
internal sealed class Bn254SpartanSoundnessTests
{
    /// <summary>The Fiat–Shamir hash delegate this test's transcripts use, backed by the BLAKE3 reference.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    /// <summary>The Fiat–Shamir squeeze delegate this test's transcripts use, backed by the BLAKE3 reference.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    /// <summary>The BN254 scalar-field canonical-reduction delegate this test proves and verifies over.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bn254BigIntegerScalarReference.GetReduce();
    /// <summary>The BN254 scalar-field addition delegate this test proves and verifies over.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bn254.Add;
    /// <summary>The BN254 scalar-field subtraction delegate this test proves and verifies over.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bn254.Subtract;
    /// <summary>The BN254 scalar-field multiplication delegate this test proves and verifies over.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bn254.Multiply;
    /// <summary>The BN254 scalar-field inversion delegate this test proves and verifies over.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bn254.Invert;
    /// <summary>The BN254 scalar-field random-sampling delegate this test's prover draws blinding scalars from.</summary>
    private static ScalarRandomDelegate Random { get; } = Bn254BigIntegerScalarReference.GetRandom();
    /// <summary>The BN254 G1 point-addition delegate this test's commitment scheme uses.</summary>
    private static G1AddDelegate G1Add { get; } = Bn254BigIntegerG1Reference.GetAdd();
    /// <summary>The BN254 G1 scalar-multiplication delegate this test's commitment scheme uses.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bn254BigIntegerG1Reference.GetScalarMultiply();
    /// <summary>The BN254 G1 multi-scalar-multiplication delegate this test's commitment scheme uses.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bn254Msm;
    /// <summary>The BN254 G1 on-curve check delegate the Hyrax commitment scheme uses.</summary>
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bn254BigIntegerG1Reference.GetIsOnCurve();
    /// <summary>The BN254 G1 prime-order-subgroup check delegate the Hyrax commitment scheme uses.</summary>
    private static G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup { get; } = Bn254BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();
    /// <summary>The BN254 G1 hash-to-curve delegate used to derive the Hyrax commitment key's generators.</summary>
    private static G1HashToCurveDelegate HashToCurve { get; } = Bn254BigIntegerG1Reference.GetHashToCurve();
    /// <summary>The multilinear-extension evaluation delegate this test's Spartan prover and verifier use.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    /// <summary>The multilinear-extension folding delegate this test's Spartan prover and verifier use.</summary>
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();

    /// <summary>The BN254 scalar-field order, used to reduce test witness values into canonical form.</summary>
    private static BigInteger Order { get; } = Bn254BigIntegerScalarReference.FieldOrder;
    /// <summary>The curve this test's circuits, witnesses, and commitment scheme operate over.</summary>
    private static CurveParameterSet Curve => CurveParameterSet.Bn254;
    /// <summary>The memory pool this test's circuits, proofs, and commitment keys are allocated from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The Hyrax commitment key's vector length, sized for this test's small one-multiplication witness.</summary>
    private const int HyraxVectorLength = 2;


    /// <summary>Verifies that the base Spartan prover throws at prove time when the witness does not satisfy the R1CS instance.</summary>
    [TestMethod]
    public void BaseSpartanUnsatisfyingWitnessThrowsAtProveTime()
    {
        //z = (1, 3, 5, 99): constraint 0 wants z[1]·z[2] = z[3], i.e. 3·5 = 15,
        //not 99. The R1CS-satisfaction check at the start of Prove rejects it.
        using SpartanProver prover = BuildBaseProver();
        using RawR1csInstance instance = BuildOneMultiplyInstance();
        using RawR1csWitness witness = BuildUnsatisfyingWitness();
        using FiatShamirTranscript transcript = FreshTranscript();

        Assert.ThrowsExactly<R1csNotSatisfiedException>(() =>
        {
            using SpartanProof _ = prover.Prove(
                instance, witness, transcript,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
                G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, Pool);
        });
    }


    /// <summary>Verifies that the masked Spartan prover throws at prove time when the witness does not satisfy the R1CS instance.</summary>
    [TestMethod]
    public void MaskedSpartanUnsatisfyingWitnessThrowsAtProveTime()
    {
        using MaskedSpartanProver prover = BuildMaskedProver();
        using RawR1csInstance instance = BuildOneMultiplyInstance();
        using RawR1csWitness witness = BuildUnsatisfyingWitness();
        using FiatShamirTranscript transcript = FreshTranscript();

        Assert.ThrowsExactly<R1csNotSatisfiedException>(() =>
        {
            using MaskedSpartanProof _ = prover.Prove(
                instance, witness, transcript,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
                G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, Pool);
        });
    }


    /// <summary>Verifies that flipping the leading byte of the proof's witness-commitment region causes verification to fail.</summary>
    [TestMethod]
    public void WitnessCommitmentBitFlipRejected()
    {
        //Flip the leading byte of the witness commitment (offset 0).
        VerifyBitFlipRejected(_ => 0, "witness commitment");
    }


    /// <summary>Verifies that flipping a byte of the proof's claim_Az region, which breaks the outer sumcheck's terminating identity, causes verification to fail.</summary>
    [TestMethod]
    public void ClaimAzBitFlipRejected()
    {
        //claim_Az sits after the witness commitment and the outer round
        //polynomials; flipping it breaks the outer terminating identity.
        VerifyBitFlipRejected(
            proof => (proof.WitnessCommitmentRowCount * WellKnownCurves.GetG1CompressedSizeBytes(proof.Curve))
                + (proof.OuterRoundCount * 3 * Scalar.SizeBytes),
            "claim_Az");
    }


    /// <summary>Proves a valid BN254 proof, flips one byte at the given offset, and asserts that verification rejects the tampered proof.</summary>
    /// <param name="offsetSelector">Computes the byte offset to flip from the original proof.</param>
    /// <param name="regionDescription">A human-readable name for the flipped region, used in the assertion message.</param>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers through using declarations; disposal happens before the assertion completes.")]
    private static void VerifyBitFlipRejected(Func<SpartanProof, int> offsetSelector, string regionDescription)
    {
        using SpartanProver prover = BuildBaseProver();
        using RawR1csInstance instance = BuildOneMultiplyInstance();
        using RawR1csWitness witness = BuildOneMultiplyWitness();
        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using SpartanProof originalProof = prover.Prove(
            instance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, Pool);

        byte[] tamperedBytes = originalProof.AsReadOnlySpan().ToArray();
        int offset = offsetSelector(originalProof);
        tamperedBytes[offset] ^= 0xFF;

        using SpartanProof tamperedProof = RehydrateProof(tamperedBytes, originalProof);

        using SpartanVerifier verifier = BuildBaseVerifier();
        using RawR1csInstance verifierInstance = BuildOneMultiplyInstance();
        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = verifier.Verify(
            tamperedProof, verifierInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze, Pool);

        Assert.IsFalse(verified, $"Verification must reject a BN254 proof with a flipped byte in the {regionDescription} region (offset {offset}).");
    }


    /// <summary>Reconstructs a <see cref="SpartanProof"/> from raw bytes, reusing a template proof's round and row counts and curve.</summary>
    private static SpartanProof RehydrateProof(byte[] proofBytes, SpartanProof template)
    {
        return SpartanProof.FromBytes(
            proofBytes,
            template.WitnessCommitmentRowCount,
            template.OuterRoundCount,
            template.InnerRoundCount,
            template.IpaRoundCount,
            template.ErrorIpaRoundCount,
            template.Curve,
            Pool);
    }


    /// <summary>Builds a base Spartan prover over a fresh Hyrax-backed proving key.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanProver.")]
    private static SpartanProver BuildBaseProver() =>
        new(new SpartanProvingKey(BuildProvider()));


    /// <summary>Builds a base Spartan verifier over a fresh Hyrax-backed verifying key.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanVerifier.")]
    private static SpartanVerifier BuildBaseVerifier() =>
        new(new SpartanVerifyingKey(BuildProvider()));


    /// <summary>Builds a masked Spartan prover over a fresh Hyrax-backed proving key.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned MaskedSpartanProver.")]
    private static MaskedSpartanProver BuildMaskedProver() =>
        new(new SpartanProvingKey(BuildProvider()));


    /// <summary>Derives the Hyrax commitment key this test's provider commits through.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the derived key transfers to the caller.")]
    private static HyraxCommitmentKey BuildCommitmentKey() =>
        HyraxCommitmentKey.Derive(
            HyraxVectorLength, WellKnownHyraxDomainLabels.CanonicalSeedV1, Curve, HashToCurve, Pool);


    /// <summary>Builds the Hyrax polynomial commitment provider this test's Spartan prover and verifier commit through.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider takes ownership of the key (ownsKey: true) and transfers to the Spartan key that consumes it.")]
    private static PolynomialCommitmentProvider BuildProvider() =>
        HyraxPolynomialCommitmentScheme.Create(
            BuildCommitmentKey(),
            Curve,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup,
            ownsKey: true);


    /// <summary>Creates a fresh Fiat–Shamir transcript for one prove or verify run, seeded with the Spartan domain label.</summary>
    private static FiatShamirTranscript FreshTranscript() =>
        FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, Pool);


    /// <summary>Builds a two-constraint R1CS instance — <c>c0: z[1]·z[2]=z[3]</c>, a padding constraint <c>c1: z[0]·z[0]=z[0]</c> — sized <c>m=2, n=4</c>.</summary>
    private static RawR1csInstance BuildOneMultiplyInstance()
    {
        int scalarSize = Scalar.SizeBytes;
        ReadOnlySpan<int> rows = [0, 1];
        ReadOnlySpan<int> aCols = [1, 0];
        ReadOnlySpan<int> bCols = [2, 0];
        ReadOnlySpan<int> cCols = [3, 0];

        Span<byte> ones = stackalloc byte[2 * scalarSize];
        WriteCanonical(BigInteger.One, ones[..scalarSize]);
        WriteCanonical(BigInteger.One, ones.Slice(scalarSize, scalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(rows, aCols, ones, 2, 4, Curve, Pool);
        R1csMatrix b = R1csMatrix.FromSortedTriples(rows, bCols, ones, 2, 4, Curve, Pool);
        R1csMatrix c = R1csMatrix.FromSortedTriples(rows, cCols, ones, 2, 4, Curve, Pool);
        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, Pool);
    }


    /// <summary>Builds the witness <c>z = (1, 3, 5, 15)</c>, which satisfies <c>c0</c> (<c>3·5=15</c>) and <c>c1</c> (<c>1·1=1</c>).</summary>
    private static RawR1csWitness BuildOneMultiplyWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[3 * scalarSize];
        WriteCanonical(new BigInteger(3), witness[..scalarSize]);
        WriteCanonical(new BigInteger(5), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger(15), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, Curve, Pool);
    }


    /// <summary>Builds the witness <c>z = (1, 3, 5, 99)</c>, which violates <c>c0</c> (<c>3·5 ≠ 99</c>).</summary>
    private static RawR1csWitness BuildUnsatisfyingWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[3 * scalarSize];
        WriteCanonical(new BigInteger(3), witness[..scalarSize]);
        WriteCanonical(new BigInteger(5), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger(99), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, Curve, Pool);
    }


    /// <summary>Reduces a <see cref="BigInteger"/> modulo <see cref="Order"/> and writes it as a canonical big-endian scalar.</summary>
    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        BigInteger nonNegative = ((value % Order) + Order) % Order;
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
