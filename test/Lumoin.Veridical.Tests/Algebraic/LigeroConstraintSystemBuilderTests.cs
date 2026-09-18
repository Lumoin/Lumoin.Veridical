using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Exercises the promoted, curve-agnostic <see cref="LigeroConstraintSystemBuilder"/>
/// directly over the P-256 base field Fp256 (via <see cref="P256BaseFieldReference"/>),
/// independent of the elliptic-curve gadget layer: boolean / constant /
/// recomposition / assert-zero primitives are proven with <see cref="LigeroProver"/>
/// and verified with <see cref="LigeroVerifier"/>, and the unsatisfiable cases are
/// shown to be unprovable. This pins the BigInteger→delegate value math and the
/// canonical-encoding contract the gadget layer relies on.
/// </summary>
[TestClass]
internal sealed class LigeroConstraintSystemBuilderTests
{
    /// <summary>The byte width of one scalar in this test's canonical scratch buffers, matching the library-wide scalar size.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The default Merkle digest width these gates hash at.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The Ligero code's inverse rate these gates commit and prove at.</summary>
    private const int InverseRate = 4;

    /// <summary>The number of Ligero columns opened per proof in these gates.</summary>
    private const int OpenedColumns = 4;

    /// <summary>The Ligero row block length these gates commit at.</summary>
    private const int Block = 64;

    /// <summary>The P-256 base-field prime, the modulus this class's deterministic randomness source reduces below.</summary>
    private static BigInteger P { get; } = P256BigIntegerG1Reference.BaseFieldPrime;

    /// <summary>The deterministic transcript seed these gates share between proving and verifying.</summary>
    private static byte[] TranscriptSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.cs-builder.v1");

    /// <summary>The deterministic seed for this class's reproducible Fp256 randomness source.</summary>
    private static byte[] RandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.cs-builder.rng.v1");

    /// <summary>The BLAKE3 Fiat-Shamir hash delegate driving both the prover's and verifier's transcripts.</summary>
    private static FiatShamirHashDelegate Hash { get; } = Blake3FiatShamirBackend.GetHash();

    /// <summary>The BLAKE3 Fiat-Shamir squeeze delegate drawing challenges from the transcript.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = Blake3FiatShamirBackend.GetSqueeze();

    /// <summary>The Merkle two-to-one compression delegate, backed by <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;


    /// <summary>Verifies that a builder combining boolean, constant, recomposition and assert-zero primitives over Fp256 proves and verifies end-to-end.</summary>
    [TestMethod]
    public void BooleanConstantAndRecompositionVerify()
    {
        var builder = NewBuilder();

        builder.AddBit(Constant(1));
        builder.AddConstant(Constant(5));

        //13 = 1101b; bits least-significant first.
        int[] bits = [AddBit(builder, 1), AddBit(builder, 0), AddBit(builder, 1), AddBit(builder, 1)];
        int recomposed = builder.AddRecomposedScalar(bits);
        Assert.IsTrue(builder.Value(recomposed).SequenceEqual(Constant(13)), "Recomposed scalar must equal 13.");

        //A constant-zero wire asserted to be zero — satisfiable.
        builder.AddAssertZero(builder.AddConstant(Constant(0)));

        using LigeroProof proof = Prove(builder);
        Assert.IsTrue(Verify(builder, proof), "An honest constraint-builder proof over Fp256 must verify.");
    }


    /// <summary>Verifies that a wire carrying a non-boolean value (2) violates the bit constraint b² = b, so the prover refuses to prove it.</summary>
    [TestMethod]
    public void NonBooleanBitIsUnprovable()
    {
        //A wire carrying 2 violates b² = b, so the prover must refuse.
        var builder = NewBuilder();
        builder.AddBit(Constant(2));

        Assert.ThrowsExactly<InvalidOperationException>(() => Prove(builder).Dispose());
    }


    /// <summary>Verifies that asserting a non-zero wire is zero is unsatisfiable, so the prover refuses to prove it.</summary>
    [TestMethod]
    public void AssertZeroOnNonZeroIsUnprovable()
    {
        //Asserting a non-zero wire is zero is unsatisfiable, so the prover refuses.
        //A satisfiable bit alongside keeps a quadratic in the system so the failure
        //is the assert-zero, not an empty quadratic tableau.
        var builder = NewBuilder();
        builder.AddBit(Constant(1));
        builder.AddAssertZero(builder.AddWire(Constant(7)));

        Assert.ThrowsExactly<InvalidOperationException>(() => Prove(builder).Dispose());
    }


    /// <summary>Adds a boolean-constrained wire holding the given small value as its canonical encoding.</summary>
    private static int AddBit(LigeroConstraintSystemBuilder builder, uint value) => builder.AddBit(Constant(value));


    /// <summary>Returns a small non-negative value as its canonical scalar encoding, via <see cref="LigeroConstraintSystemBuilder.EncodeConstant"/>.</summary>
    private static byte[] Constant(uint value)
    {
        byte[] bytes = new byte[ScalarSize];
        LigeroConstraintSystemBuilder.EncodeConstant(value, bytes);

        return bytes;
    }


    /// <summary>Every constraint-system builder this test created, tracked for disposal at test cleanup.</summary>
    private List<LigeroConstraintSystemBuilder> Builders { get; } = [];


    /// <summary>Disposes every constraint-system builder this test created.</summary>
    [TestCleanup]
    public void DisposeBuilders()
    {
        foreach(LigeroConstraintSystemBuilder builder in Builders)
        {
            builder.Dispose();
        }
    }


    /// <summary>Creates a P-256 Ligero constraint-system builder at this class's fixed Ligero parameters, tracking it for disposal at test cleanup.</summary>
    private LigeroConstraintSystemBuilder NewBuilder()
    {
        var builder = new LigeroConstraintSystemBuilder(
            P256BaseFieldReference.GetAdd(), P256BaseFieldReference.GetSubtract(), P256BaseFieldReference.GetMultiply(),
            P256BaseFieldReference.GetInvert(), P256BaseFieldReference.GetReduce(),
            CurveParameterSet.None, InverseRate, OpenedColumns, Block, BaseMemoryPool.Shared);
        Builders.Add(builder);

        return builder;
    }


    /// <summary>Proves with pooled snapshots that remain owned until the prover returns.</summary>
    private static LigeroProof Prove(LigeroConstraintSystemBuilder builder)
    {
        using IMemoryOwner<byte>? witnessOwner = builder.WitnessBytes();
        using IMemoryOwner<byte>? targetsOwner = builder.TargetBytes();

        return LigeroProver.Prove(
            builder.BuildParameters(), (witnessOwner?.Memory ?? Memory<byte>.Empty).Span, builder.LinearConstraintCount, builder.LinearConstraints(),
            (targetsOwner?.Memory ?? Memory<byte>.Empty).Span, builder.QuadraticConstraints(), TranscriptSeed,
            new DeterministicFp256Random(RandomnessSeed).AsDelegate(),
            P256BaseFieldReference.GetAdd(), P256BaseFieldReference.GetSubtract(), P256BaseFieldReference.GetMultiply(),
            P256BaseFieldReference.GetInvert(), P256BaseFieldReference.GetReduce(),
            Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
            CurveParameterSet.None, BaseMemoryPool.Shared);
    }


    /// <summary>Verifies with a pooled target snapshot owned until verification returns.</summary>
    private static bool Verify(LigeroConstraintSystemBuilder builder, LigeroProof proof)
    {
        using IMemoryOwner<byte>? targetsOwner = builder.TargetBytes();

        return LigeroVerifier.Verify(
            builder.BuildParameters(), proof, builder.LinearConstraintCount, builder.LinearConstraints(),
            (targetsOwner?.Memory ?? Memory<byte>.Empty).Span, builder.QuadraticConstraints(), TranscriptSeed,
            P256BaseFieldReference.GetAdd(), P256BaseFieldReference.GetSubtract(), P256BaseFieldReference.GetMultiply(),
            P256BaseFieldReference.GetInvert(), P256BaseFieldReference.GetReduce(),
            Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
            CurveParameterSet.None, BaseMemoryPool.Shared);
    }


    /// <summary>Computes the Merkle two-to-one compression of <paramref name="left"/> and <paramref name="right"/> via BLAKE3.</summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>A reproducible Fp256 randomness source: a BLAKE3 extendable-output hash of the seed concatenated with an incrementing counter, reduced modulo the base-field prime.</summary>
    private sealed class DeterministicFp256Random
    {
        /// <summary>The fixed seed this source's counter-based draws are derived from.</summary>
        private byte[] Seed { get; }

        /// <summary>The number of draws produced so far, mixed into each draw's input so successive draws differ.</summary>
        private int counter;

        /// <summary>Creates a randomness source copying the given seed.</summary>
        public DeterministicFp256Random(ReadOnlySpan<byte> seed) => this.Seed = seed.ToArray();

        /// <summary>Returns this source's draw as a <see cref="ScalarRandomDelegate"/>.</summary>
        public ScalarRandomDelegate AsDelegate() => Fill;

        /// <summary>Draws the next pseudo-random Fp256 scalar into <paramref name="destination"/> by hashing the seed and counter and reducing the result modulo the base-field prime, returning <paramref name="inboundTag"/> unchanged.</summary>
        private Tag Fill(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> input = stackalloc byte[Seed.Length + sizeof(int)];
            Seed.CopyTo(input);
            BinaryPrimitives.WriteInt32BigEndian(input[Seed.Length..], counter);
            counter++;

            Span<byte> wide = stackalloc byte[64];
            Blake3.Hash(input, wide);
            BigInteger reduced = new BigInteger(wide, isUnsigned: true, isBigEndian: true) % P;
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
