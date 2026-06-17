using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
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
/// Shared delegate fixtures, transcript factory, and R1CS-instance /
/// witness builders used across the masked-Spartan test classes
/// (<c>MaskedSpartanRoundtripTests</c>, <c>MaskedSpartanFailureTests</c>,
/// <c>MaskedSpartanFixtureTests</c>,
/// <c>MaskedSpartanIndistinguishabilityTests</c>,
/// <c>MaskedSpartanSoundnessTests</c>). Centralised so each test
/// class focuses on its property contract rather than re-wiring the
/// backend delegates.
/// </summary>
internal static class MaskedSpartanTestFixtures
{
    public static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    public static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    public static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    public static ScalarAddDelegate Add { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();
    public static ScalarSubtractDelegate Subtract { get; } = Bls12Curve381BigIntegerScalarReference.GetSubtract();
    public static ScalarMultiplyDelegate Multiply { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();
    public static ScalarInvertDelegate Invert { get; } = Bls12Curve381BigIntegerScalarReference.GetInvert();
    public static ScalarRandomDelegate ScalarRandom { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();
    public static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    public static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    public static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    public static G1HashToCurveDelegate HashToCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    public static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    public static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();


    //The widest test-family sumcheck (rows or columns up to 2^4) bounds the
    //statistical masks' single-row vector commitments; computed from the
    //policy so a ledger change propagates.
    private const int LargestTestSumcheckVariableCount = 4;

    /// <summary>
    /// The masked prover's masks are committed as single-row vectors needing
    /// one Hyrax generator per coordinate (<c>2^ℓ₂</c> of the Pedersen/IPA
    /// mask shape) — typically more than the witness matrix's column count on
    /// the small test instances, so the key builders floor the requested
    /// vector length here.
    /// </summary>
    public static int MaskedVectorLengthFloor { get; } = WellKnownStatisticalMaskParameters.CreatePedersenIpa(
        LargestTestSumcheckVariableCount, WellKnownMaskedSpartanParameters.OuterMaskPerVariableDegree).CoefficientCount;


    public static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers to the returned MaskedSpartanProver via its constructor chain.")]
    public static MaskedSpartanProver BuildMaskedProver(int hyraxVectorLength)
    {
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            Math.Max(hyraxVectorLength, MaskedVectorLengthFloor),
            WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bls12Curve381,
            HashToCurve,
            BaseMemoryPool.Shared);
        var provingKey = new SpartanProvingKey(BuildProvider(commitmentKey));

        return new MaskedSpartanProver(provingKey);
    }


    /// <summary>
    /// Builds a masked prover whose provider closes over <paramref name="random"/>,
    /// so the witness/error-opening blinding the prover draws shares the caller's
    /// deterministic stream — required for byte-stability fixtures where the same
    /// stream must also be threaded into <c>Prove</c>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers to the returned MaskedSpartanProver via its constructor chain.")]
    public static MaskedSpartanProver BuildMaskedProver(int hyraxVectorLength, ScalarRandomDelegate random)
    {
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            Math.Max(hyraxVectorLength, MaskedVectorLengthFloor),
            WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bls12Curve381,
            HashToCurve,
            BaseMemoryPool.Shared);
        var provingKey = new SpartanProvingKey(BuildProvider(commitmentKey, random));

        return new MaskedSpartanProver(provingKey);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers to the returned MaskedSpartanVerifier via its constructor chain.")]
    public static MaskedSpartanVerifier BuildMaskedVerifier(int hyraxVectorLength)
    {
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            Math.Max(hyraxVectorLength, MaskedVectorLengthFloor),
            WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bls12Curve381,
            HashToCurve,
            BaseMemoryPool.Shared);
        var verifyingKey = new SpartanVerifyingKey(BuildProvider(commitmentKey));

        return new MaskedSpartanVerifier(verifyingKey);
    }


    /// <summary>Builds a masked verifier whose provider closes over <paramref name="random"/>; verification draws no blinding, so the random source is immaterial to its output.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers to the returned MaskedSpartanVerifier via its constructor chain.")]
    public static MaskedSpartanVerifier BuildMaskedVerifier(int hyraxVectorLength, ScalarRandomDelegate random)
    {
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            Math.Max(hyraxVectorLength, MaskedVectorLengthFloor),
            WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bls12Curve381,
            HashToCurve,
            BaseMemoryPool.Shared);
        var verifyingKey = new SpartanVerifyingKey(BuildProvider(commitmentKey, random));

        return new MaskedSpartanVerifier(verifyingKey);
    }


    /// <summary>
    /// Wraps a Hyrax commitment key in the scheme-agnostic provider Spartan
    /// now consumes. The provider takes ownership of <paramref name="commitmentKey"/>
    /// (<c>ownsKey: true</c>), so whatever owns the provider disposes the key.
    /// </summary>
    public static PolynomialCommitmentProvider BuildProvider(HyraxCommitmentKey commitmentKey)
    {
        return BuildProvider(commitmentKey, ScalarRandom);
    }


    /// <summary>
    /// Wraps a Hyrax commitment key in the provider, closing over
    /// <paramref name="random"/> for the commit/open blinding. The provider
    /// takes ownership of <paramref name="commitmentKey"/>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider takes ownership of the key (ownsKey: true) and transfers to whatever owns the provider.")]
    public static PolynomialCommitmentProvider BuildProvider(HyraxCommitmentKey commitmentKey, ScalarRandomDelegate random)
    {
        return HyraxPolynomialCommitmentScheme.Create(
            commitmentKey,
            CurveParameterSet.Bls12Curve381,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm,
            ownsKey: true);
    }


    /// <summary>
    /// One multiplication plus padding: constraint 0
    /// <c>z[1] · z[2] = z[3]</c>, constraint 1 <c>z[0]·z[0] = z[0]</c>.
    /// Dimensions (m=2, n=4). Vector length 2 for Hyrax.
    /// </summary>
    public static RawR1csInstance BuildOneMultiplyInstance()
    {
        int scalarSize = Scalar.SizeBytes;
        int[] aRows = [0, 1];
        int[] aCols = [1, 0];
        int[] bRows = [0, 1];
        int[] bCols = [2, 0];
        int[] cRows = [0, 1];
        int[] cCols = [3, 0];

        byte[] onesValues = new byte[2 * scalarSize];
        WriteCanonical(BigInteger.One, onesValues.AsSpan(0, scalarSize));
        WriteCanonical(BigInteger.One, onesValues.AsSpan(scalarSize, scalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(aRows, aCols, onesValues, 2, 4, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix b = R1csMatrix.FromSortedTriples(bRows, bCols, onesValues, 2, 4, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix c = R1csMatrix.FromSortedTriples(cRows, cCols, onesValues, 2, 4, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared);
    }


    public static RawR1csWitness BuildOneMultiplyWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        byte[] witnessBytes = new byte[3 * scalarSize];
        WriteCanonical(new BigInteger(3), witnessBytes.AsSpan(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(5), witnessBytes.AsSpan(1 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(15), witnessBytes.AsSpan(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witnessBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Alternative valid witness for the one-multiply instance:
    /// (2, 7, 14). z = (1, 2, 7, 14). Used by indistinguishability
    /// tests to construct two different valid witnesses.
    /// </summary>
    public static RawR1csWitness BuildAlternativeOneMultiplyWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        byte[] witnessBytes = new byte[3 * scalarSize];
        WriteCanonical(new BigInteger(2), witnessBytes.AsSpan(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(7), witnessBytes.AsSpan(1 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(14), witnessBytes.AsSpan(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witnessBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Two multiplications: constraint 0 <c>z[1]·z[2] = z[3]</c>,
    /// constraint 1 <c>z[4]·z[5] = z[6]</c>. Dimensions (m=2, n=8).
    /// Vector length 4 for Hyrax.
    /// </summary>
    public static RawR1csInstance BuildTwoMultiplyInstance()
    {
        int scalarSize = Scalar.SizeBytes;
        int[] aRows = [0, 1];
        int[] aCols = [1, 4];
        int[] bRows = [0, 1];
        int[] bCols = [2, 5];
        int[] cRows = [0, 1];
        int[] cCols = [3, 6];

        byte[] onesValues = new byte[2 * scalarSize];
        WriteCanonical(BigInteger.One, onesValues.AsSpan(0, scalarSize));
        WriteCanonical(BigInteger.One, onesValues.AsSpan(scalarSize, scalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(aRows, aCols, onesValues, 2, 8, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix b = R1csMatrix.FromSortedTriples(bRows, bCols, onesValues, 2, 8, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        R1csMatrix c = R1csMatrix.FromSortedTriples(cRows, cCols, onesValues, 2, 8, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared);
    }


    public static RawR1csWitness BuildTwoMultiplyWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        //(3, 5, 15, 2, 7, 14). z = (1, 3, 5, 15, 2, 7, 14, 0). c0: 3*5=15, c1: 2*7=14.
        byte[] witnessBytes = new byte[7 * scalarSize];
        WriteCanonical(new BigInteger(3), witnessBytes.AsSpan(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(5), witnessBytes.AsSpan(1 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(15), witnessBytes.AsSpan(2 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(2), witnessBytes.AsSpan(3 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(7), witnessBytes.AsSpan(4 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(14), witnessBytes.AsSpan(5 * scalarSize, scalarSize));
        WriteCanonical(BigInteger.Zero, witnessBytes.AsSpan(6 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witnessBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Constructs an UNSATISFYING witness for the one-multiply instance:
    /// z[1] · z[2] != z[3] (3·5 = 15 but z[3] = 99 here, so c0 violated).
    /// Used by soundness tests to confirm the prover throws.
    /// </summary>
    public static RawR1csWitness BuildUnsatisfyingWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        byte[] witnessBytes = new byte[3 * scalarSize];
        WriteCanonical(new BigInteger(3), witnessBytes.AsSpan(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(5), witnessBytes.AsSpan(1 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(99), witnessBytes.AsSpan(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witnessBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    public static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        bytes.CopyTo(destination[(destination.Length - bytes.Length)..]);
    }
}