using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Commitments.Longfellow;
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
/// End-to-end gate for the Ligero argument: a correctly generated proof
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
    /// <summary>The byte width of a canonical scalar in every field this test class exercises.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>A satisfying witness: <c>W[2] = W[0]·W[1]</c> (6 = 2·3) and <c>W[5] = W[3]·W[4]</c> (20 = 4·5).</summary>
    private static int[] WitnessValues { get; } = [2, 3, 6, 4, 5, 20];
    /// <summary>The number of witness wires, matching <see cref="WitnessValues"/>'s length.</summary>
    private const int WitnessCount = 6;

    /// <summary>The two quadratic constraints <see cref="WitnessValues"/> satisfies: <c>W[2] = W[0]·W[1]</c> and <c>W[5] = W[3]·W[4]</c>.</summary>
    private static LigeroQuadraticConstraint[] QuadraticConstraints { get; } =
    [
        new LigeroQuadraticConstraint(0, 1, 2),
        new LigeroQuadraticConstraint(3, 4, 5),
    ];

    /// <summary>The number of linear constraints below.</summary>
    private const int LinearConstraintCount = 2;
    /// <summary>Two linear constraints: <c>c0: W[0] + W[1] = 5</c> and <c>c1: 2·W[3] = 8</c>.</summary>
    private static LigeroLinearConstraint[] LinearConstraints { get; } =
    [
        new LigeroLinearConstraint(0, 0, Coefficient(1)),
        new LigeroLinearConstraint(0, 1, Coefficient(1)),
        new LigeroLinearConstraint(1, 3, Coefficient(2)),
    ];
    /// <summary>The target values <c>[5, 8]</c> the linear constraints above must sum to.</summary>
    private static int[] LinearTargetValues { get; } = [5, 8];

    /// <summary>
    /// The Ligero code's inverse rate. The interleaved Reed–Solomon proximity error is about
    /// <c>(1 − δ)^OpenedColumns</c> with δ ≈ 1 − 1/InverseRate the code's relative distance (plus
    /// lower-order terms); at rate 1/4, δ ≈ 3/4 and each opened column contributes about 2 bits, so
    /// production targets 128-bit soundness with about 64 columns. This test class uses a smaller
    /// query count for speed: prover/verifier correctness is independent of the count, and only the
    /// soundness margin scales with it.
    /// </summary>
    private const int InverseRate = 4;
    /// <summary>The number of columns opened per proof; see <see cref="InverseRate"/> for how this test's smaller count trades soundness margin for speed without affecting correctness.</summary>
    private const int OpenedColumns = 8;
    /// <summary>The Ligero code's block length.</summary>
    private const int Block = 16;

    /// <summary>The Fiat–Shamir transcript seed for the honest-proof and rejection tests that do not perturb the public input.</summary>
    private static byte[] TranscriptSeed { get; } = "Lumoin.Veridical.Ligero.ArgumentRoundtrip.Test"u8.ToArray();
    /// <summary>The prover-randomness seed, the ASCII bytes for <c>rand</c>.</summary>
    private static byte[] RandomnessSeed { get; } = [0x72, 0x61, 0x6E, 0x64];

    /// <summary>The two-to-one Merkle compression function, delegated to <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Blake3TwoToOne { get; } = HashTwoToOne;


    /// <summary>Verifies that a correctly generated proof over a satisfying witness verifies, across the small Mersenne-prime field, the P-256 scalar field, and the P-256 base field.</summary>
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

        Assert.IsTrue(verified, $"A correctly generated proof over the {field} must verify.");
    }


    /// <summary>Verifies that re-wiring a quadratic constraint to a relation the witness does not satisfy causes verification to fail, across all three fields.</summary>
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


    /// <summary>Verifies that claiming a linear-constraint target different from the true sum causes verification to fail, across all three fields.</summary>
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


    /// <summary>Verifies that flipping a byte of an opened column causes verification to fail because its Merkle leaf no longer matches the committed root, across all three fields.</summary>
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


    /// <summary>Verifies that replaying a different public-input seed draws different challenges and opened-column indices, so a genuine proof fails to verify, across all three fields.</summary>
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


    /// <summary>Verifies that fixed blinding randomness yields a byte-identical commitment and byte-identical responses across two independent proving runs, since the prover's arithmetic is a pure function of its inputs.</summary>
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


    /// <summary>Verifies that the prover throws when the witness's quadratic relations hold but a linear constraint is violated, across all three fields.</summary>
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


    /// <summary>Verifies that supplying a row-extender factory (the FFT-accelerated encode path) produces a byte-identical commitment and responses compared to the default barycentric encode, over the P-256 base field — the field the FFT convolution engine serves.</summary>
    [TestMethod]
    public void TheProofIsByteIdenticalWithAndWithoutTheRowExtenderFactory()
    {
        //Pins the tableau's block/doubleBlock extender threading and the
        //dot-response aext branch in the fast suite: without this gate the only
        //prove that installs a factory is the [Slow] end-to-end credential
        //test, and a transposed-extender wiring mutation would go unnoticed
        //until it ran. P-256 base field only — that is the field the FFT
        //convolution engine serves.
        FieldBackend backend = Backend("p-256 base");
        LigeroParameters parameters = NewParameters();

        using LigeroProof reference = BuildProof(backend, parameters);
        using BaseMemoryPool fftPool = new();
        using Fp256RealFft fft = NewFft(backend, fftPool);
        using Fp256LigeroRowExtenders extenders = NewRowExtenders(backend, fft, fftPool);
        using LigeroProof accelerated = BuildProof(backend, parameters, RandomnessSeed, LinearTargetValues, extenders.Create);

        Assert.IsTrue(accelerated.Root.AsReadOnlySpan().SequenceEqual(reference.Root.AsReadOnlySpan()), "The commitment root must be byte-identical with and without the extender.");
        Assert.IsTrue(accelerated.LowDegreeResponse.SequenceEqual(reference.LowDegreeResponse), "y_ldt must be byte-identical with and without the extender.");
        Assert.IsTrue(accelerated.DotResponse.SequenceEqual(reference.DotResponse), "y_dot must be byte-identical with and without the extender.");
        Assert.IsTrue(accelerated.QuadraticResponse.SequenceEqual(reference.QuadraticResponse), "y_quad must be byte-identical with and without the extender.");

        bool verified = VerifyProof(backend, parameters, accelerated, QuadraticConstraints, LinearTargetValues, TranscriptSeed);
        Assert.IsTrue(verified, "The extender-accelerated proof must verify.");
    }


    /// <summary>Creates extenders borrowing a caller-owned FFT through proof generation.</summary>
    /// <param name="backend">The arithmetic delegates.</param>
    /// <param name="fft">The live FFT.</param>
    /// <param name="pool">The caller pool.</param>
    /// <returns>The disposable row extenders.</returns>
    private static Fp256LigeroRowExtenders NewRowExtenders(FieldBackend backend, Fp256RealFft fft, BaseMemoryPool pool)
    {
        return new Fp256LigeroRowExtenders(fft, backend.Add, backend.Subtract, backend.Multiply, backend.Invert, OfScalarCanonical, CurveParameterSet.None, pool);
    }


    /// <summary>Creates an FFT owned through the accelerated proof operation.</summary>
    /// <param name="backend">The arithmetic delegates.</param>
    /// <param name="pool">The caller pool retained through FFT disposal.</param>
    /// <returns>The disposable FFT.</returns>
    private static Fp256RealFft NewFft(FieldBackend backend, BaseMemoryPool pool)
    {
        Span<byte> root = stackalloc byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnity(root);

        return new Fp256RealFft(root, LongfellowFp256Encoding.OmegaOrder, backend.Add, backend.Subtract, backend.Multiply, backend.Invert, OfScalarCanonical, CurveParameterSet.None, pool);
    }


    /// <summary>Writes <paramref name="value"/> as a canonical big-endian scalar into <paramref name="destination"/>, zero-padded on the left.</summary>
    private static void OfScalarCanonical(uint value, Span<byte> destination)
    {
        destination.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(destination[^sizeof(uint)..], value);
    }


    /// <summary>Builds the Ligero parameters shared by every field backend in this test class.</summary>
    private static LigeroParameters NewParameters() =>
        new(WitnessCount, QuadraticConstraints.Length, InverseRate, OpenedColumns, Block);


    /// <summary>Builds a proof using the default randomness seed and linear targets.</summary>
    private static LigeroProof BuildProof(FieldBackend backend, LigeroParameters parameters) =>
        BuildProof(backend, parameters, RandomnessSeed, LinearTargetValues);


    /// <summary>Builds a Ligero proof over the fixed witness and constraints for the given field backend, randomness seed, and target values, optionally through a row-extender factory.</summary>
    private static LigeroProof BuildProof(FieldBackend backend, LigeroParameters parameters, ReadOnlySpan<byte> randomnessSeed, ReadOnlySpan<int> targetValues, LigeroRowExtenderFactory? rowExtenderFactory = null)
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
            BaseMemoryPool.Shared,
            rowExtenderFactory);
    }


    /// <summary>Verifies a Ligero proof against the given quadratic constraints, linear target values, and transcript seed for the given field backend.</summary>
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


    /// <summary>Resolves the named field's arithmetic delegates: <c>"small field"</c> (a hand-checkable Mersenne prime), <c>"p-256"</c> (the P-256 scalar field), or <c>"p-256 base"</c> (the P-256 base field Longfellow's ECDSA circuit runs in).</summary>
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
        //here proves the substrate for the native in-circuit ECDSA gadget.
        "p-256 base" => new FieldBackend(
            P256BaseFieldReference.GetAdd(),
            P256BaseFieldReference.GetSubtract(),
            P256BaseFieldReference.GetMultiply(),
            P256BaseFieldReference.GetInvert(),
            P256BaseFieldReference.GetReduce(),
            P256BaseFieldReference.FieldOrder),
        _ => throw new ArgumentOutOfRangeException(nameof(field), field, "Unknown field."),
    };


    /// <summary>Encodes <paramref name="value"/> as a canonical scalar stored in a <c>byte[]</c> rather than scratch memory, since <see cref="LigeroLinearConstraint"/> retains the coefficient beyond the call.</summary>
    private static ReadOnlyMemory<byte> Coefficient(int value)
    {
        //A stored constraint coefficient, not scratch, so a byte[] is the right shape.
        byte[] bytes = new byte[ScalarSize];
        WriteCanonical(value, bytes);

        return bytes;
    }


    /// <summary>Writes each value in <paramref name="values"/> as a canonical big-endian scalar into consecutive <see cref="ScalarSize"/>-sized slots of <paramref name="destination"/>.</summary>
    private static void FillScalars(ReadOnlySpan<int> values, Span<byte> destination)
    {
        for(int i = 0; i < values.Length; i++)
        {
            WriteCanonical(values[i], destination.Slice(i * ScalarSize, ScalarSize));
        }
    }


    /// <summary>Computes the two-to-one Merkle compression of <paramref name="left"/> and <paramref name="right"/> using BLAKE3.</summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * ScalarSize];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>Writes <paramref name="value"/> as a canonical big-endian 32-bit scalar into <paramref name="destination"/>, zero-padded on the left.</summary>
    private static void WriteCanonical(int value, Span<byte> destination)
    {
        destination.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(destination[^sizeof(uint)..], (uint)value);
    }


    /// <summary>The field arithmetic backend under test for one named field. The reference delegates ignore the curve identity, so the same field-generic prover and verifier code exercises every field this class names.</summary>
    private sealed class FieldBackend(
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarReduceDelegate reduce,
        BigInteger fieldOrder)
    {
        /// <summary>The field addition delegate.</summary>
        public ScalarAddDelegate Add { get; } = add;
        /// <summary>The field subtraction delegate.</summary>
        public ScalarSubtractDelegate Subtract { get; } = subtract;
        /// <summary>The field multiplication delegate.</summary>
        public ScalarMultiplyDelegate Multiply { get; } = multiply;
        /// <summary>The field inversion delegate.</summary>
        public ScalarInvertDelegate Invert { get; } = invert;
        /// <summary>The field reduction delegate.</summary>
        public ScalarReduceDelegate Reduce { get; } = reduce;
        /// <summary>The field's prime order.</summary>
        public BigInteger FieldOrder { get; } = fieldOrder;
    }


    /// <summary>A reproducible prover-randomness source over an arbitrary prime field: each call hashes <c>seed ‖ counter</c> through BLAKE3 and reduces the wide output modulo the field order. Test-only; production code draws randomness from a CSPRNG.</summary>
    private sealed class DeterministicFieldRandom
    {
        /// <summary>The fixed seed mixed with the call counter to derive each output.</summary>
        private byte[] Seed { get; }
        /// <summary>The prime field order each output is reduced modulo.</summary>
        private BigInteger FieldOrder { get; }
        /// <summary>The number of outputs produced so far; mixed into the hash input so consecutive calls differ.</summary>
        private int counter;


        /// <summary>Captures the seed and field order this instance will draw reduced randomness from.</summary>
        public DeterministicFieldRandom(ReadOnlySpan<byte> seed, BigInteger fieldOrder)
        {
            this.Seed = seed.ToArray();
            this.FieldOrder = fieldOrder;
            counter = 0;
        }


        /// <summary>Exposes this instance's <see cref="Fill"/> method as a <see cref="ScalarRandomDelegate"/>.</summary>
        public ScalarRandomDelegate AsDelegate() => Fill;


        /// <summary>Derives the next output by hashing the seed and call counter with BLAKE3 and reducing the wide result modulo the field order, then advances the counter.</summary>
        private Tag Fill(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> input = stackalloc byte[Seed.Length + sizeof(int)];
            Seed.CopyTo(input);
            BinaryPrimitives.WriteInt32BigEndian(input[Seed.Length..], counter);
            counter++;

            Span<byte> wide = stackalloc byte[64];
            Blake3.Hash(input, wide);

            BigInteger value = new(wide, isUnsigned: true, isBigEndian: true);
            BigInteger reduced = value % FieldOrder;

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
