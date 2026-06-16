using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Commitments.Ligero.Gadgets;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The statement-binding hardening for the ECDSA verifier: deriving the Fiat-Shamir
/// transcript seed from the public statement (domain ‖ Q ‖ e ‖ r ‖ s) makes a proof
/// non-transferable. The public inputs are already bound as AddConstant targets the
/// verifier supplies; binding the transcript to them too (the cheap caller-side
/// alternative to the R1CS path's AbsorbR1csInstance) means a proof for one statement
/// yields different challenges — and is rejected — under any other, without touching
/// the audited prover/verifier.
/// </summary>
[TestClass]
internal sealed class EcdsaStatementBindingTests
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    private const int InverseRate = 4;
    private const int OpenedColumns = 4;
    private const int Block = 64;

    private static readonly BigInteger P = P256BigIntegerG1Reference.BaseFieldPrime;

    private static readonly byte[] Domain = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.ecdsa-p256.v1");
    private static readonly byte[] OtherDomain = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.ecdsa-p256.v2");
    private static readonly byte[] RandomnessSeed = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.stmt.rng.v1");

    private static readonly FiatShamirHashDelegate Hash = Blake3FiatShamirBackend.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = Blake3FiatShamirBackend.GetSqueeze();
    private static readonly MerkleHashDelegate Merkle = HashTwoToOne;


    [TestMethod]
    public void DeriveTranscriptSeedIsStatementSpecific()
    {
        EcdsaPublicInputs statement = MakeInputs(5);
        byte[] seed = EcdsaVerificationGadgetExtensions.DeriveTranscriptSeed(statement, Domain, Hash, WellKnownHashAlgorithms.Blake3);

        Assert.IsTrue(
            seed.AsSpan().SequenceEqual(EcdsaVerificationGadgetExtensions.DeriveTranscriptSeed(MakeInputs(5), Domain, Hash, WellKnownHashAlgorithms.Blake3)),
            "The same statement must yield the same seed.");
        Assert.IsFalse(
            seed.AsSpan().SequenceEqual(EcdsaVerificationGadgetExtensions.DeriveTranscriptSeed(MakeInputs(6), Domain, Hash, WellKnownHashAlgorithms.Blake3)),
            "A different statement (s) must yield a different seed.");
        Assert.IsFalse(
            seed.AsSpan().SequenceEqual(EcdsaVerificationGadgetExtensions.DeriveTranscriptSeed(statement, OtherDomain, Hash, WellKnownHashAlgorithms.Blake3)),
            "A different domain separator must yield a different seed.");
    }


    [TestMethod]
    public void AProofIsRejectedUnderADifferentStatementSeed()
    {
        //A small circuit proved under one statement's seed is rejected under another's
        //seed: the seed feeds the transcript, so different statements draw different
        //challenges. (Demonstrated cheaply here; the full-width gate exercises it on the
        //real gadget.)
        byte[] seed = EcdsaVerificationGadgetExtensions.DeriveTranscriptSeed(MakeInputs(5), Domain, Hash, WellKnownHashAlgorithms.Blake3);
        byte[] otherSeed = EcdsaVerificationGadgetExtensions.DeriveTranscriptSeed(MakeInputs(6), Domain, Hash, WellKnownHashAlgorithms.Blake3);

        var builder = NewBuilder();
        builder.AddBit(Bytes(1));
        builder.AddAssertZero(builder.AddConstant(Bytes(0)));

        using LigeroProof proof = Prove(builder, seed);
        Assert.IsTrue(Verify(builder, proof, seed), "An honest proof verifies under its own statement seed.");
        Assert.IsFalse(Verify(builder, proof, otherSeed), "A proof must be rejected under a different statement's seed.");
    }


    //Arbitrary canonical inputs distinguished by s — DeriveTranscriptSeed hashes the
    //bytes, so these need not be a valid signature.
    private static EcdsaPublicInputs MakeInputs(int s) => new(Bytes(11), Bytes(22), Bytes(33), Bytes(44), Bytes(s));


    private static byte[] Bytes(int value)
    {
        byte[] result = new byte[ScalarSize];
        LigeroConstraintSystemBuilder.EncodeConstant((uint)value, result);

        return result;
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


    private static LigeroProof Prove(LigeroConstraintSystemBuilder builder, byte[] seed) => LigeroProver.Prove(
        builder.BuildParameters(), builder.WitnessBytes(), builder.LinearConstraintCount, builder.LinearConstraints(),
        builder.TargetBytes(), builder.QuadraticConstraints(), seed,
        new DeterministicFp256Random(RandomnessSeed).AsDelegate(),
        P256BaseFieldReference.GetAdd(), P256BaseFieldReference.GetSubtract(), P256BaseFieldReference.GetMultiply(),
        P256BaseFieldReference.GetInvert(), P256BaseFieldReference.GetReduce(),
        Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
        CurveParameterSet.None, BaseMemoryPool.Shared);


    private static bool Verify(LigeroConstraintSystemBuilder builder, LigeroProof proof, byte[] seed) => LigeroVerifier.Verify(
        builder.BuildParameters(), proof, builder.LinearConstraintCount, builder.LinearConstraints(),
        builder.TargetBytes(), builder.QuadraticConstraints(), seed,
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
