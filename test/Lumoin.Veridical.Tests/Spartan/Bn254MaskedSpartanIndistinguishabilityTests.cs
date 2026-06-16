using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Text;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Zero-knowledge randomness-flow leg for BN254 masked Spartan: under a fixed
/// masking seed the proof bytes change with the witness (the prover actually
/// consumes the witness), and for a fixed witness they change with the seed
/// (the masking randomness is actually applied). The BN254 counterpart of the
/// two sanity legs in <see cref="MaskedSpartanIndistinguishabilityTests"/>.
/// </summary>
/// <remarks>
/// The BLS class's third leg — a chi-squared byte-distribution smoke test over
/// the blinded sections — is intentionally not mirrored here: the masking math
/// it probes is field-independent (only the scalar field changes), and it costs
/// ~100 reference-backend proofs, so a BN254 copy would add cost without new
/// signal. The two reproducibility legs below are what exercise the BN254
/// randomness flow that the round-trips do not touch.
/// </remarks>
[TestClass]
internal sealed class Bn254MaskedSpartanIndistinguishabilityTests
{
    private const int SensitivityIterations = 10;
    private const int SeedLengthBytes = 16;
    private const int HyraxVectorLength = 2;


    [TestMethod]
    public void MaskedProofsForDifferentWitnessesHaveDifferentBytes()
    {
        //Fixed seed across both proofs; only the witness varies. A prover that
        //ignored the witness would yield byte-equal proofs under a fixed seed.
        Span<byte> seed = stackalloc byte[SeedLengthBytes];
        DeriveSeed("bn254-witness-sensitivity", 0, seed);
        byte[] seedBytes = seed.ToArray();

        Gen.Select(Gen.Int[1, 100], Gen.Int[1, 100], Gen.Int[1, 100], Gen.Int[1, 100])
            .Where((a1, b1, a2, b2) => a1 != a2 || b1 != b2)
            .Sample((a1, b1, a2, b2) =>
            {
                using RawR1csWitness w1 = BuildWitness(a1, b1);
                using RawR1csWitness w2 = BuildWitness(a2, b2);
                byte[] proof1 = ProduceProofBytes(w1, seedBytes);
                byte[] proof2 = ProduceProofBytes(w2, seedBytes);

                return !proof1.AsSpan().SequenceEqual(proof2);
            }, iter: SensitivityIterations);
    }


    [TestMethod]
    public void MaskedProofsForSameWitnessDifferentSeedsHaveDifferentBytes()
    {
        Gen.Select(Gen.Int[1, 100], Gen.Int[1, 100], Gen.Int, Gen.Int)
            .Where((_, _, s1, s2) => s1 != s2)
            .Sample((a, b, s1, s2) =>
            {
                Span<byte> seed1 = stackalloc byte[SeedLengthBytes];
                Span<byte> seed2 = stackalloc byte[SeedLengthBytes];
                DeriveSeed("bn254-seed-sensitivity-1", s1, seed1);
                DeriveSeed("bn254-seed-sensitivity-2", s2, seed2);

                using RawR1csWitness w1 = BuildWitness(a, b);
                using RawR1csWitness w2 = BuildWitness(a, b);
                byte[] proof1 = ProduceProofBytes(w1, seed1);
                byte[] proof2 = ProduceProofBytes(w2, seed2);

                return !proof1.AsSpan().SequenceEqual(proof2);
            }, iter: SensitivityIterations);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers through using declarations; disposal happens before the bytes are returned.")]
    private static byte[] ProduceProofBytes(RawR1csWitness witness, ReadOnlySpan<byte> seed)
    {
        var rng = new DeterministicScalarRandom(seed);
        ScalarRandomDelegate random = rng.AsDelegate();

        //The provider's commit/open close over the random delegate supplying the
        //Hyrax blinding, so it must share the per-seed RNG that the masking blinds
        //draw from to keep the whole proof's randomness seed-driven.
        using MaskedSpartanProver prover = BuildMaskedProver(random);
        using RawR1csInstance instance = BuildOneMultiplyInstance();
        using FiatShamirTranscript transcript = FreshTranscript();

        using MaskedSpartanProof proof = prover.Prove(
            instance, witness, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, Pool);

        return proof.AsReadOnlySpan().ToArray();
    }


    //z = (1, a, b, a·b): a satisfying witness for the one-multiply instance.
    private static RawR1csWitness BuildWitness(int a, int b)
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[3 * scalarSize];
        WriteCanonical(new BigInteger(a), witness[..scalarSize]);
        WriteCanonical(new BigInteger(b), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger((long)a * b), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, Curve, Pool);
    }


    private static void DeriveSeed(string label, int counter, Span<byte> destination)
    {
        //Deterministic per-(label, counter) seed via BLAKE3 — for reproducibility,
        //not entropy (the project bans System.Random for insecure randomness).
        byte[] labelBytes = Encoding.UTF8.GetBytes(label);
        Span<byte> input = stackalloc byte[labelBytes.Length + sizeof(int)];
        labelBytes.AsSpan().CopyTo(input);
        BinaryPrimitives.WriteInt32BigEndian(input[labelBytes.Length..], counter);
        Lumoin.Veridical.Hashing.Blake3.Hash(input, destination);
    }


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


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned MaskedSpartanProver.")]
    private static MaskedSpartanProver BuildMaskedProver(ScalarRandomDelegate random) =>
        new(new SpartanProvingKey(HyraxPolynomialCommitmentScheme.Create(
            HyraxCommitmentKey.Derive(
                Math.Max(HyraxVectorLength, MaskedSpartanTestFixtures.MaskedVectorLengthFloor),
                WellKnownHyraxDomainLabels.CanonicalSeedV1, Curve, HashToCurve, Pool),
            Curve,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm,
            ownsKey: true)));


    private static FiatShamirTranscript FreshTranscript() =>
        FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, Pool);


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


    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bn254BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bn254.Add;
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bn254.Subtract;
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bn254.Multiply;
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bn254.Invert;
    private static G1AddDelegate G1Add { get; } = Bn254BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bn254BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bn254Msm;
    private static G1HashToCurveDelegate HashToCurve { get; } = Bn254BigIntegerG1Reference.GetHashToCurve();
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();

    private static readonly BigInteger Order = Bn254BigIntegerScalarReference.FieldOrder;
    private static CurveParameterSet Curve => CurveParameterSet.Bn254;
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;
}
