using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Commitments.Ligero;

/// <summary>
/// End-to-end gate for the Ligero argument (LF.4b.4–LF.4b.6): an honest proof
/// over a satisfying witness verifies, and the verifier rejects a flipped
/// quadratic constraint, a tampered linear target, a corrupted opened column and
/// a mismatched public input. It runs first over the small Mersenne-prime field
/// (hand-checkable arithmetic) and then over the P-256 scalar field (the curve
/// Longfellow consumes), confirming the field-generic prover and verifier behave
/// identically on both.
/// </summary>
[TestClass]
internal sealed class LigeroArgumentRoundtripTests
{
    private const int ScalarSize = Scalar.SizeBytes;

    //A satisfying witness: W[2] = W[0]·W[1] (6 = 2·3), W[5] = W[3]·W[4] (20 = 4·5).
    private static readonly int[] WitnessValues = [2, 3, 6, 4, 5, 20];
    private const int WitnessCount = 6;

    private static readonly LigeroQuadraticConstraint[] QuadraticConstraints =
    [
        new LigeroQuadraticConstraint(0, 1, 2),
        new LigeroQuadraticConstraint(3, 4, 5),
    ];

    //Two linear constraints: c0: W[0] + W[1] = 5; c1: 2·W[3] = 8.
    private const int LinearConstraintCount = 2;
    private static readonly LigeroLinearConstraint[] LinearConstraints =
    [
        new LigeroLinearConstraint(0, 0, Coefficient(1)),
        new LigeroLinearConstraint(0, 1, Coefficient(1)),
        new LigeroLinearConstraint(1, 3, Coefficient(2)),
    ];
    private static readonly int[] LinearTargetValues = [5, 8];

    //Soundness parameters. The interleaved-Reed-Solomon proximity error is about
    //(1 − δ)^OpenedColumns, with δ ≈ 1 − 1/InverseRate the RS relative distance
    //(plus lower-order RS/affine-line terms). At InverseRate = 4 the rate is 1/4,
    //so δ ≈ 3/4 and each opened column contributes ≈ 2 bits; production targets
    //128-bit soundness with ≈ 64 columns. This gate uses a smaller query count
    //for speed — correctness of the prover/verifier is independent of the count,
    //only the soundness margin scales with it.
    private const int InverseRate = 4;
    private const int OpenedColumns = 8;
    private const int Block = 16;

    private static readonly byte[] TranscriptSeed = [0x4C, 0x46, 0x34, 0x62, 0x36]; //"LF4b6"
    private static readonly byte[] RandomnessSeed = [0x72, 0x61, 0x6E, 0x64];        //"rand"

    private static readonly MerkleHashDelegate Blake3TwoToOne = HashTwoToOne;


    [TestMethod]
    [DataRow("small field")]
    [DataRow("p-256")]
    [DataRow("p-256 base")]
    public void HonestProofVerifies(string field)
    {
        FieldBackend backend = Backend(field);
        LigeroParameters parameters = NewParameters();

        using LigeroProof proof = BuildProof(backend, parameters);
        bool verified = VerifyProof(backend, parameters, proof, QuadraticConstraints, LinearTargetValues, TranscriptSeed);

        Assert.IsTrue(verified, $"An honest proof over the {field} must verify.");
    }


    [TestMethod]
    [DataRow("small field")]
    [DataRow("p-256")]
    [DataRow("p-256 base")]
    public void FlippedQuadraticConstraintRejects(string field)
    {
        FieldBackend backend = Backend(field);
        LigeroParameters parameters = NewParameters();
        using LigeroProof proof = BuildProof(backend, parameters);

        //Re-wire the second constraint to W[5] = W[3]·W[3] (16 ≠ 20): a false
        //statement the proof was not built for. The verifier's constraint matrix
        //changes, so the dot-product test no longer matches.
        LigeroQuadraticConstraint[] flipped =
        [
            QuadraticConstraints[0],
            new LigeroQuadraticConstraint(3, 3, 5),
        ];

        bool verified = VerifyProof(backend, parameters, proof, flipped, LinearTargetValues, TranscriptSeed);
        Assert.IsFalse(verified, $"A flipped quadratic constraint must be rejected ({field}).");
    }


    [TestMethod]
    [DataRow("small field")]
    [DataRow("p-256")]
    [DataRow("p-256 base")]
    public void TamperedLinearTargetRejects(string field)
    {
        FieldBackend backend = Backend(field);
        LigeroParameters parameters = NewParameters();
        using LigeroProof proof = BuildProof(backend, parameters);

        //Claim W[0] + W[1] = 6 rather than the true 5; the dot-product value
        //check Σ b·αl ≠ Σ y_dot[r..block) catches it.
        int[] tamperedTargets = [6, 8];

        bool verified = VerifyProof(backend, parameters, proof, QuadraticConstraints, tamperedTargets, TranscriptSeed);
        Assert.IsFalse(verified, $"A tampered linear target must be rejected ({field}).");
    }


    [TestMethod]
    [DataRow("small field")]
    [DataRow("p-256")]
    [DataRow("p-256 base")]
    public void CorruptedOpenedColumnRejects(string field)
    {
        FieldBackend backend = Backend(field);
        LigeroParameters parameters = NewParameters();
        using LigeroProof proof = BuildProof(backend, parameters);

        //Flip a byte of the first opened column; its Merkle leaf no longer
        //matches the committed root.
        Span<byte> column = proof.OpenedColumnMutable(0);
        column[0] ^= 0x01;

        bool verified = VerifyProof(backend, parameters, proof, QuadraticConstraints, LinearTargetValues, TranscriptSeed);
        Assert.IsFalse(verified, $"A corrupted opened column must be rejected ({field}).");
    }


    [TestMethod]
    [DataRow("small field")]
    [DataRow("p-256")]
    [DataRow("p-256 base")]
    public void MismatchedPublicInputRejects(string field)
    {
        FieldBackend backend = Backend(field);
        LigeroParameters parameters = NewParameters();
        using LigeroProof proof = BuildProof(backend, parameters);

        //A verifier replaying a different public-input seed draws different
        //challenges and opened-column indices, so the openings do not line up.
        byte[] otherSeed = [0x4C, 0x46, 0x34, 0x62, 0x37];

        bool verified = VerifyProof(backend, parameters, proof, QuadraticConstraints, LinearTargetValues, otherSeed);
        Assert.IsFalse(verified, $"A proof bound to a different public input must be rejected ({field}).");
    }


    [TestMethod]
    public void ProvingIsDeterministicInTheProverRandomness()
    {
        //Fixed blinding randomness must yield byte-identical responses and the
        //same commitment — the prover arithmetic is a pure function of its inputs.
        FieldBackend backend = Backend("small field");
        LigeroParameters parameters = NewParameters();

        using LigeroProof first = BuildProof(backend, parameters);
        using LigeroProof second = BuildProof(backend, parameters);

        Assert.IsTrue(first.Root.AsReadOnlySpan().SequenceEqual(second.Root.AsReadOnlySpan()), "Fixed randomness must yield the same commitment.");
        Assert.IsTrue(first.LowDegreeResponse.SequenceEqual(second.LowDegreeResponse), "Fixed randomness must yield the same y_ldt.");
        Assert.IsTrue(first.DotResponse.SequenceEqual(second.DotResponse), "Fixed randomness must yield the same y_dot.");
        Assert.IsTrue(first.QuadraticResponse.SequenceEqual(second.QuadraticResponse), "Fixed randomness must yield the same y_quad.");
    }


    [TestMethod]
    [DataRow("small field")]
    [DataRow("p-256")]
    [DataRow("p-256 base")]
    public void RejectsAnUnsatisfiedLinearConstraintAtProvingTime(string field)
    {
        //A witness whose quadratic relations hold but whose linear constraint is
        //violated must be refused by the prover, not silently proved.
        FieldBackend backend = Backend(field);
        LigeroParameters parameters = NewParameters();

        int[] brokenTargets = [99, 8]; //claim W[0] + W[1] = 99
        Assert.ThrowsExactly<InvalidOperationException>(() =>
            BuildProof(backend, parameters, RandomnessSeed, brokenTargets).Dispose());
    }


    private static LigeroParameters NewParameters() =>
        new(WitnessCount, QuadraticConstraints.Length, InverseRate, OpenedColumns, Block);


    private static LigeroProof BuildProof(FieldBackend backend, LigeroParameters parameters) =>
        BuildProof(backend, parameters, RandomnessSeed, LinearTargetValues);


    private static LigeroProof BuildProof(FieldBackend backend, LigeroParameters parameters, ReadOnlySpan<byte> randomnessSeed, ReadOnlySpan<int> targetValues)
    {
        Span<byte> witnesses = stackalloc byte[WitnessCount * ScalarSize];
        FillScalars(WitnessValues, witnesses);

        Span<byte> targets = stackalloc byte[LinearConstraintCount * ScalarSize];
        FillScalars(targetValues, targets);

        DeterministicFieldRandom random = new(randomnessSeed, backend.FieldOrder);

        return LigeroProver.Prove(
            parameters,
            witnesses,
            LinearConstraintCount,
            LinearConstraints,
            targets,
            QuadraticConstraints,
            TranscriptSeed,
            random.AsDelegate(),
            backend.Add,
            backend.Subtract,
            backend.Multiply,
            backend.Invert,
            backend.Reduce,
            Blake3FiatShamirBackend.GetHash(),
            Blake3FiatShamirBackend.GetSqueeze(),
            Blake3FiatShamirBackend.GetHash(),
            Blake3TwoToOne,
            WellKnownHashAlgorithms.Blake3,
            CurveParameterSet.None,
            BaseMemoryPool.Shared);
    }


    private static bool VerifyProof(
        FieldBackend backend,
        LigeroParameters parameters,
        LigeroProof proof,
        ReadOnlySpan<LigeroQuadraticConstraint> quadraticConstraints,
        ReadOnlySpan<int> targetValues,
        ReadOnlySpan<byte> transcriptSeed)
    {
        Span<byte> targets = stackalloc byte[LinearConstraintCount * ScalarSize];
        FillScalars(targetValues, targets);

        return LigeroVerifier.Verify(
            parameters,
            proof,
            LinearConstraintCount,
            LinearConstraints,
            targets,
            quadraticConstraints,
            transcriptSeed,
            backend.Add,
            backend.Subtract,
            backend.Multiply,
            backend.Invert,
            backend.Reduce,
            Blake3FiatShamirBackend.GetHash(),
            Blake3FiatShamirBackend.GetSqueeze(),
            Blake3FiatShamirBackend.GetHash(),
            Blake3TwoToOne,
            WellKnownHashAlgorithms.Blake3,
            CurveParameterSet.None,
            BaseMemoryPool.Shared);
    }


    private static FieldBackend Backend(string field) => field switch
    {
        "small field" => new FieldBackend(
            SmallPrimeFieldScalars.GetAdd(),
            SmallPrimeFieldScalars.GetSubtract(),
            SmallPrimeFieldScalars.GetMultiply(),
            SmallPrimeFieldScalars.GetInvert(),
            SmallPrimeFieldScalars.GetReduce(),
            SmallPrimeFieldScalars.FieldOrder),
        "p-256" => new FieldBackend(
            P256BigIntegerScalarReference.GetAdd(),
            P256BigIntegerScalarReference.GetSubtract(),
            P256BigIntegerScalarReference.GetMultiply(),
            P256BigIntegerScalarReference.GetInvert(),
            P256BigIntegerScalarReference.GetReduce(),
            P256BigIntegerScalarReference.FieldOrder),
        //The P-256 BASE field Fp — the field Longfellow's ECDSA circuit runs in
        //(the sumcheck field equals the curve base field). Exercising the argument
        //here proves the substrate for the native in-circuit ECDSA gadget (LF.5).
        "p-256 base" => new FieldBackend(
            P256BaseFieldReference.GetAdd(),
            P256BaseFieldReference.GetSubtract(),
            P256BaseFieldReference.GetMultiply(),
            P256BaseFieldReference.GetInvert(),
            P256BaseFieldReference.GetReduce(),
            P256BaseFieldReference.FieldOrder),
        _ => throw new ArgumentOutOfRangeException(nameof(field), field, "Unknown field."),
    };


    private static ReadOnlyMemory<byte> Coefficient(int value)
    {
        //A stored constraint coefficient, not scratch, so a byte[] is the right shape.
        byte[] bytes = new byte[ScalarSize];
        WriteCanonical(value, bytes);

        return bytes;
    }


    private static void FillScalars(ReadOnlySpan<int> values, Span<byte> destination)
    {
        for(int i = 0; i < values.Length; i++)
        {
            WriteCanonical(values[i], destination.Slice(i * ScalarSize, ScalarSize));
        }
    }


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * ScalarSize];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    private static void WriteCanonical(int value, Span<byte> destination)
    {
        destination.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(destination[^sizeof(uint)..], (uint)value);
    }


    //The field arithmetic backend under test. The reference delegates ignore the
    //curve identity, so both fields are exercised by the same field-generic code.
    private sealed class FieldBackend(
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarReduceDelegate reduce,
        BigInteger fieldOrder)
    {
        public ScalarAddDelegate Add { get; } = add;
        public ScalarSubtractDelegate Subtract { get; } = subtract;
        public ScalarMultiplyDelegate Multiply { get; } = multiply;
        public ScalarInvertDelegate Invert { get; } = invert;
        public ScalarReduceDelegate Reduce { get; } = reduce;
        public BigInteger FieldOrder { get; } = fieldOrder;
    }


    //A reproducible prover-randomness source over an arbitrary prime field: each
    //call hashes seed ‖ counter through BLAKE3-XOF and reduces the wide output
    //modulo the field order. Test-only; production draws from a CSPRNG.
    private sealed class DeterministicFieldRandom
    {
        private readonly byte[] seed;
        private readonly BigInteger fieldOrder;
        private int counter;


        public DeterministicFieldRandom(ReadOnlySpan<byte> seed, BigInteger fieldOrder)
        {
            this.seed = seed.ToArray();
            this.fieldOrder = fieldOrder;
            counter = 0;
        }


        public ScalarRandomDelegate AsDelegate() => Fill;


        private Tag Fill(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> input = stackalloc byte[seed.Length + sizeof(int)];
            seed.CopyTo(input);
            BinaryPrimitives.WriteInt32BigEndian(input[seed.Length..], counter);
            counter++;

            Span<byte> wide = stackalloc byte[64];
            Blake3.Hash(input, wide);

            BigInteger value = new(wide, isUnsigned: true, isBigEndian: true);
            BigInteger reduced = value % fieldOrder;

            destination.Clear();
            reduced.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true);
            if(written < destination.Length)
            {
                int shift = destination.Length - written;
                destination[..written].CopyTo(destination[shift..]);
                destination[..shift].Clear();
            }

            return inboundTag;
        }
    }
}
