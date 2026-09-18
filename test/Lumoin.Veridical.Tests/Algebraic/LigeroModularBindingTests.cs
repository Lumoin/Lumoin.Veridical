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
/// Soundness of the modular bindings the Longfellow ECDSA verifier uses to tie its
/// public inputs to the witnessed nonce point, over the P-256 base field Fp256:
/// the nonzero check (r, s ∈ [1, n−1]), the public-scalar canonical-bit binding
/// (the ladder consumes exactly the pinned scalar), and — the soundness-critical one
/// — <c>r = R.x mod n</c> via <see cref="LigeroConstraintSystemBuilder.AddReduceModOrder"/>.
/// </summary>
/// <remarks>
/// The headline attack is the mod-p alias: with the witnessed x-coordinate
/// <c>rx = 3</c>, the false remainder <c>r' = rx + p − n</c> is &lt; n and satisfies a
/// naive field tie <c>r' + n ≡ rx (mod p)</c> (it differs from the truth by exactly
/// p). The binding proves the INTEGER identity <c>rx = quotient·n + r</c> with a
/// ripple-carry adder whose terms never exceed 3, so the alias — which needs
/// <c>r' + n = rx + p</c> as integers — cannot pass under either quotient.
/// </remarks>
[TestClass]
internal sealed class LigeroModularBindingTests
{
    /// <summary>The byte width of a canonical P-256 base-field scalar.</summary>
    private const int ScalarSize = Scalar.SizeBytes;
    /// <summary>The byte width of a BLAKE3 digest, as used by the Merkle and Ligero commitments in these tests.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The Ligero code's inverse rate these tests use.</summary>
    private const int InverseRate = 4;
    /// <summary>The number of Ligero columns opened per proof in these tests.</summary>
    private const int OpenedColumns = 4;
    /// <summary>The Ligero code's block length these tests use.</summary>
    private const int Block = 64;

    /// <summary>The P-256 base-field prime.</summary>
    private static BigInteger P { get; } = P256BigIntegerG1Reference.BaseFieldPrime;
    /// <summary>The P-256 scalar-field order — the modulus <see cref="LigeroConstraintSystemBuilder.AddReduceModOrder"/> reduces against.</summary>
    private static BigInteger N { get; } = WellKnownCurves.GetScalarFieldOrder(CurveParameterSet.P256);
    /// <summary>The canonical big-endian encoding of <see cref="N"/>.</summary>
    private static byte[] NBytes { get; } = Bytes(N);

    /// <summary>The Fiat–Shamir transcript seed shared by every proof and verification in this test class.</summary>
    private static byte[] TranscriptSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.modbind.v1");
    /// <summary>The seed for the deterministic prover-randomness source these tests share.</summary>
    private static byte[] RandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.modbind.rng.v1");

    /// <summary>The BLAKE3 Fiat–Shamir hash delegate this test's transcripts and proofs use.</summary>
    private static FiatShamirHashDelegate Hash { get; } = Blake3FiatShamirBackend.GetHash();
    /// <summary>The BLAKE3 Fiat–Shamir squeeze delegate this test's transcripts and proofs use.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = Blake3FiatShamirBackend.GetSqueeze();
    /// <summary>The two-to-one Merkle compression function, delegated to <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;


    /// <summary>Verifies that a nonzero wire satisfies and proves the nonzero check end to end, that forcing the checked wire to zero violates <c>wire·inv = 1</c>, and that a wire already known to be zero cannot even have the check built against it.</summary>
    [TestMethod]
    public void NonzeroCheckPassesForNonzeroAndRejectsZero()
    {
        //A nonzero wire satisfies and proves end-to-end.
        var honest = NewBuilder();
        honest.AddNonzeroCheck(Wire(honest, 7));
        Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(honest), "A nonzero wire must satisfy the nonzero check.");
        using LigeroProof proof = Prove(honest);
        Assert.IsTrue(Verify(honest, proof), "An honest nonzero-check proof must verify.");

        //Injecting zero into the checked wire violates wire·inv = 1.
        var attacked = NewBuilder();
        int wire = Wire(attacked, 7);
        attacked.AddNonzeroCheck(wire);
        attacked.SetWireForTesting(wire, Bytes(0));
        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(attacked), "A zero value must violate the nonzero check.");

        //A wire known to be zero has no inverse, so the check cannot even be built.
        var zeroBuilder = NewBuilder();
        Assert.ThrowsExactly<InvalidOperationException>(() => zeroBuilder.AddNonzeroCheck(zeroBuilder.AddConstant(Bytes(0))));
    }


    /// <summary>Verifies that a scalar below <c>n</c> pins canonically through <c>AddPublicScalarBits</c>, that its most-significant-first bit decomposition recomposes to the scalar and proves end to end, and that a scalar equal to <c>n</c> violates the <c>&lt; n</c> bound.</summary>
    [TestMethod]
    public void PublicScalarBitsBindCanonicalValueAndRejectAtOrAboveLimit()
    {
        //A scalar < n pins canonically and its bits recompose (most-significant first)
        //to the scalar.
        var builder = NewBuilder();
        (int wire, WireWord bitsMsb) = builder.AddPublicScalarBits(Bytes(0x9a), NBytes);
        Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), "A scalar < n must satisfy AddPublicScalarBits.");
        Assert.AreEqual(new BigInteger(0x9a), new BigInteger(builder.Value(wire), isUnsigned: true, isBigEndian: true), "The pinned wire must hold the scalar.");
        Assert.AreEqual(256, bitsMsb.Length, "A 256-bit scalar decomposition is returned.");

        using LigeroProof proof = Prove(builder);
        Assert.IsTrue(Verify(builder, proof), "An honest public-scalar binding must verify.");

        //A scalar equal to n fails the < n bound.
        var atLimit = NewBuilder();
        atLimit.AddPublicScalarBits(NBytes, NBytes);
        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(atLimit), "A scalar equal to n must violate the < n bound.");
    }


    /// <summary>Verifies that <c>AddReduceModOrder</c> pins the public remainder to <c>value mod n</c> for witnessed values spanning both the quotient-0 and quotient-1 regimes.</summary>
    [TestMethod]
    public void ReduceModOrderBindsRemainderAcrossTheRange()
    {
        //For witnessed values spanning the quotient-0 and quotient-1 regimes, the
        //binding fixes the public remainder to value mod n.
        foreach(BigInteger value in new[] { BigInteger.Zero, BigInteger.One, N - 1, N, N + 7, P - 1 })
        {
            BigInteger remainder = ((value % N) + N) % N;

            var builder = NewBuilder();
            (int rWire, _) = builder.AddReduceModOrder(Wire(builder, value), Bytes(remainder), NBytes);
            Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), $"value {value} with remainder {remainder} must satisfy the binding.");
            Assert.AreEqual(remainder, new BigInteger(builder.Value(rWire), isUnsigned: true, isBigEndian: true), "The pinned remainder wire must hold value mod n.");
        }
    }


    /// <summary>Verifies one full-width end-to-end proof and verification of the modular-reduction binding (the ripple-carry adder over about 1.5k quadratics), for a value in the quotient-1 regime.</summary>
    [TestMethod]
    public void ReduceModOrderHonestProvesAndVerifies()
    {
        //One full-width end-to-end gate of the binding (the ripple-carry adder over
        //~1.5k quadratics): an honest instance proves and verifies. value ≥ n exercises
        //the quotient-1 path.
        BigInteger value = N + 1234;
        BigInteger remainder = ((value % N) + N) % N;

        var builder = NewBuilder();
        builder.AddReduceModOrder(Wire(builder, value), Bytes(remainder), NBytes);

        using LigeroProof proof = Prove(builder);
        Assert.IsTrue(Verify(builder, proof), "An honest r = value mod n binding must verify.");
    }


    /// <summary>Verifies that the mod-p alias attack — a false remainder that satisfies a naive field tie but not the integer identity — is rejected under both the honest quotient and a maliciously forced quotient.</summary>
    [TestMethod]
    public void ReduceModOrderRejectsTheModpAlias()
    {
        //The headline attack: rx = 3, false remainder r' = 3 + p − n (which is < n and
        //satisfies a naive field tie). The honest builder picks quotient 0 (3 < n) and
        //the adder demands r' = 3 — false. The malicious prover would instead force
        //quotient 1; that demands r' + n = 3 as integers, i.e. 3 + p = 3 — also false.
        //Both are rejected; the range check alone would have let r' through.
        BigInteger alias = 3 + P - N;
        Assert.IsLessThan(N, alias, "The alias must pass the < n range check (so the adder is what rejects it).");

        var honest = NewBuilder();
        honest.AddReduceModOrder(Wire(honest, 3), Bytes(alias), NBytes);
        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(honest), "The alias must be rejected under the honest quotient.");
        Assert.ThrowsExactly<InvalidOperationException>(() => Prove(honest).Dispose());

        var forced = NewBuilder();
        forced.AddReduceModOrderWithQuotientForTesting(Wire(forced, 3), Bytes(alias), NBytes, quotient: true);
        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(forced), "The alias must be rejected even with the malicious quotient 1.");
    }


    /// <summary>Verifies that a plainly wrong remainder is rejected in both the quotient-0 and quotient-1 regimes.</summary>
    [TestMethod]
    public void ReduceModOrderRejectsAWrongRemainder()
    {
        //A plainly wrong remainder (11 for value 10) is rejected: the adder demands
        //11 = 10.
        var below = NewBuilder();
        below.AddReduceModOrder(Wire(below, 10), Bytes(11), NBytes);
        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(below), "A wrong remainder must be rejected (quotient-0 regime).");

        //And in the quotient-1 regime: value = n + 3 has remainder 3, not 4.
        var above = NewBuilder();
        above.AddReduceModOrder(Wire(above, N + 3), Bytes(4), NBytes);
        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(above), "A wrong remainder must be rejected (quotient-1 regime).");
    }


    /// <summary>Adds a wire to <paramref name="builder"/> pinned to <paramref name="value"/>.</summary>
    private static int Wire(LigeroConstraintSystemBuilder builder, BigInteger value) => builder.AddWire(Bytes(value));


    /// <summary>Encodes <paramref name="value"/> as a canonical big-endian scalar, zero-padded on the left.</summary>
    private static byte[] Bytes(BigInteger value)
    {
        byte[] result = new byte[ScalarSize];
        value.TryWriteBytes(result, out int written, isUnsigned: true, isBigEndian: true);
        if(written < ScalarSize)
        {
            int shift = ScalarSize - written;
            result.AsSpan(0, written).CopyTo(result.AsSpan(shift));
            result.AsSpan(0, shift).Clear();
        }

        return result;
    }


    /// <summary>Every builder created by <see cref="NewBuilder"/> in the current test, disposed at cleanup.</summary>
    private List<LigeroConstraintSystemBuilder> Builders { get; } = [];


    /// <summary>Disposes every builder this test created.</summary>
    [TestCleanup]
    public void DisposeBuilders()
    {
        foreach(LigeroConstraintSystemBuilder builder in Builders)
        {
            builder.Dispose();
        }
    }


    /// <summary>Creates a P-256 base-field constraint-system builder and tracks it for disposal at test cleanup.</summary>
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


    /// <summary>Computes the two-to-one Merkle compression of <paramref name="left"/> and <paramref name="right"/> using BLAKE3.</summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>A reproducible Fp256 randomness source: BLAKE3 of <c>seed ‖ counter</c> reduced modulo the base-field prime.</summary>
    private sealed class DeterministicFp256Random
    {
        /// <summary>The fixed seed mixed with the call counter to derive each output.</summary>
        private byte[] Seed { get; }
        /// <summary>The number of outputs produced so far; mixed into the hash input so consecutive calls differ.</summary>
        private int counter;

        /// <summary>Captures the seed this instance will draw reduced randomness from.</summary>
        public DeterministicFp256Random(ReadOnlySpan<byte> seed) => this.Seed = seed.ToArray();

        /// <summary>Exposes this instance's <see cref="Fill"/> method as a <see cref="ScalarRandomDelegate"/>.</summary>
        public ScalarRandomDelegate AsDelegate() => Fill;

        /// <summary>Derives the next output by hashing the seed and call counter with BLAKE3 and reducing the wide result modulo the base-field prime, then advances the counter.</summary>
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
