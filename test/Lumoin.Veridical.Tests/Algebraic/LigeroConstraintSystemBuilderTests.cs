using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using System;
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
    private const int ScalarSize = Scalar.SizeBytes;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    private const int InverseRate = 4;
    private const int OpenedColumns = 4;
    private const int Block = 64;

    private static readonly BigInteger P = P256BigIntegerG1Reference.BaseFieldPrime;

    private static readonly byte[] TranscriptSeed = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.cs-builder.v1");
    private static readonly byte[] RandomnessSeed = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.cs-builder.rng.v1");

    private static readonly FiatShamirHashDelegate Hash = Blake3FiatShamirBackend.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = Blake3FiatShamirBackend.GetSqueeze();
    private static readonly MerkleHashDelegate Merkle = HashTwoToOne;


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


    [TestMethod]
    public void NonBooleanBitIsUnprovable()
    {
        //A wire carrying 2 violates b² = b, so the prover must refuse.
        var builder = NewBuilder();
        builder.AddBit(Constant(2));

        Assert.ThrowsExactly<InvalidOperationException>(() => Prove(builder).Dispose());
    }


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


    private static int AddBit(LigeroConstraintSystemBuilder builder, uint value) => builder.AddBit(Constant(value));


    private static byte[] Constant(uint value)
    {
        byte[] bytes = new byte[ScalarSize];
        LigeroConstraintSystemBuilder.EncodeConstant(value, bytes);

        return bytes;
    }


    private readonly List<LigeroConstraintSystemBuilder> builders = [];


    [TestCleanup]
    public void DisposeBuilders()
    {
        foreach(LigeroConstraintSystemBuilder builder in builders)
        {
            builder.Dispose();
        }
    }


    private LigeroConstraintSystemBuilder NewBuilder()
    {
        var builder = new LigeroConstraintSystemBuilder(
            P256BaseFieldReference.GetAdd(), P256BaseFieldReference.GetSubtract(), P256BaseFieldReference.GetMultiply(),
            P256BaseFieldReference.GetInvert(), P256BaseFieldReference.GetReduce(),
            CurveParameterSet.None, InverseRate, OpenedColumns, Block, BaseMemoryPool.Shared);
        builders.Add(builder);

        return builder;
    }


    private static LigeroProof Prove(LigeroConstraintSystemBuilder builder) => LigeroProver.Prove(
        builder.BuildParameters(), builder.WitnessBytes(), builder.LinearConstraintCount, builder.LinearConstraints(),
        builder.TargetBytes(), builder.QuadraticConstraints(), TranscriptSeed,
        new DeterministicFp256Random(RandomnessSeed).AsDelegate(),
        P256BaseFieldReference.GetAdd(), P256BaseFieldReference.GetSubtract(), P256BaseFieldReference.GetMultiply(),
        P256BaseFieldReference.GetInvert(), P256BaseFieldReference.GetReduce(),
        Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
        CurveParameterSet.None, BaseMemoryPool.Shared);


    private static bool Verify(LigeroConstraintSystemBuilder builder, LigeroProof proof) => LigeroVerifier.Verify(
        builder.BuildParameters(), proof, builder.LinearConstraintCount, builder.LinearConstraints(),
        builder.TargetBytes(), builder.QuadraticConstraints(), TranscriptSeed,
        P256BaseFieldReference.GetAdd(), P256BaseFieldReference.GetSubtract(), P256BaseFieldReference.GetMultiply(),
        P256BaseFieldReference.GetInvert(), P256BaseFieldReference.GetReduce(),
        Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
        CurveParameterSet.None, BaseMemoryPool.Shared);


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    //A reproducible Fp256 randomness source: BLAKE3-XOF of seed‖counter reduced
    //modulo the base-field prime.
    private sealed class DeterministicFp256Random
    {
        private readonly byte[] seed;
        private int counter;

        public DeterministicFp256Random(ReadOnlySpan<byte> seed) => this.seed = seed.ToArray();

        public ScalarRandomDelegate AsDelegate() => Fill;

        private Tag Fill(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> input = stackalloc byte[seed.Length + sizeof(int)];
            seed.CopyTo(input);
            BinaryPrimitives.WriteInt32BigEndian(input[seed.Length..], counter);
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
