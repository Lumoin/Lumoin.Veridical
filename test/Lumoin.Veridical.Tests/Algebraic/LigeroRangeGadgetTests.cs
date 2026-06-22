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
/// Soundness of the canonical-bits and range gadgets that the Longfellow ECDSA
/// verifier's cross-modulus bindings stand on, over the P-256 base field Fp256
/// (<see cref="P256BaseFieldReference"/>). The decisive tests construct the
/// <em>attack</em> — a bit pattern whose integer value lands at or above the bound,
/// the kind a non-canonical decomposition (<c>v</c> vs <c>v + p</c>) would smuggle —
/// and assert the constraint system rejects it, checked directly with
/// <see cref="LigeroConstraintEvaluator"/> (fast, prover-independent) and confirmed
/// end-to-end against <see cref="LigeroProver"/> for representative cases.
/// </summary>
/// <remarks>
/// Over a field with <c>p &lt; 2²⁵⁶</c> a bitCount-bit recomposition is not unique:
/// for a value below <c>2²⁵⁶ − p</c> both <c>v</c> and <c>v + p</c> are 256-bit and
/// recompose mod <c>p</c> to the same element. The comparator stays on <c>{0,1}</c>
/// operands (a lexicographic prefix-equal chain) and never reforms a wrappable sum,
/// so it bounds the <em>literal</em> integer the bits encode — that is what makes the
/// bound sound here.
/// </remarks>
[TestClass]
internal sealed class LigeroRangeGadgetTests
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    private const int InverseRate = 4;
    private const int OpenedColumns = 4;
    private const int Block = 64;

    private static readonly BigInteger P = P256BigIntegerG1Reference.BaseFieldPrime;
    private static readonly BigInteger N = WellKnownCurves.GetScalarFieldOrder(CurveParameterSet.P256);
    private static readonly byte[] NBytes = Bytes(N);

    private static readonly byte[] TranscriptSeed = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.range.v1");
    private static readonly byte[] RandomnessSeed = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.range.rng.v1");

    private static readonly FiatShamirHashDelegate Hash = Blake3FiatShamirBackend.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = Blake3FiatShamirBackend.GetSqueeze();
    private static readonly MerkleHashDelegate Merkle = HashTwoToOne;


    [TestMethod]
    public void AssertLessThanConstantAcceptsBelowAndRejectsAtOrAbove()
    {
        //The comparator in isolation over 8-bit literal bit values against 200: the
        //only constraints are the prefix-equal chain, so acceptance is exactly v < 200.
        const int width = 8;
        byte[] limit = Bytes(200);
        foreach(int value in new[] { 0, 1, 199 })
        {
            var builder = NewBuilder();
            builder.AddAssertLessThanConstant(BitsOf(builder, value, width), limit);
            Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), $"{value} < 200 must satisfy the comparator.");
        }

        foreach(int value in new[] { 200, 201, 255 })
        {
            var builder = NewBuilder();
            builder.AddAssertLessThanConstant(BitsOf(builder, value, width), limit);
            Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(builder), $"{value} ≥ 200 must violate the comparator.");
        }
    }


    [TestMethod]
    public void AssertLessThanConstantHonestProvesAndAtBoundIsUnprovable()
    {
        //The evaluator agrees with the prover: a below-bound instance proves and
        //verifies; an at-bound one is unprovable (the prover refuses an unsatisfiable
        //witness). Small width keeps the O(n²) barycentric encoder fast.
        const int width = 8;
        byte[] limit = Bytes(200);

        var honest = NewBuilder();
        honest.AddAssertLessThanConstant(BitsOf(honest, 199, width), limit);
        using LigeroProof proof = Prove(honest);
        Assert.IsTrue(Verify(honest, proof), "An honest below-bound comparator proof must verify.");

        var atBound = NewBuilder();
        atBound.AddAssertLessThanConstant(BitsOf(atBound, 200, width), limit);
        Assert.ThrowsExactly<InvalidOperationException>(() => Prove(atBound).Dispose());
    }


    [TestMethod]
    public void AssertLessThanOrderAcceptsBelowAndRejectsAtOrAbove()
    {
        //Full 256-bit comparator against the curve order n, with the literal bits set
        //directly (a fully consistent witness — no stale intermediates). This is the
        //decisive bound: any 256-bit B ≥ n is rejected, including the alias-band cases
        //(n ≤ B < p) a naive mod-p check would miss. Checked with the evaluator (no
        //prove), so it is fast at full width.
        foreach(BigInteger value in new[] { BigInteger.Zero, BigInteger.One, N - 1 })
        {
            var builder = NewBuilder();
            builder.AddAssertLessThanConstant(BitsOf(builder, value, 256), NBytes);
            Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), $"{value} < n must satisfy the comparator.");
        }

        foreach(BigInteger value in new[] { N, N + 1, P - 1 })
        {
            var builder = NewBuilder();
            builder.AddAssertLessThanConstant(BitsOf(builder, value, 256), NBytes);
            Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(builder), $"{value} ≥ n must violate the comparator.");
        }
    }


    [TestMethod]
    public void CanonicalBitsAcceptHonestValuesAndRejectNonCanonical()
    {
        //Honest wire values (always < p) decompose canonically and satisfy.
        foreach(BigInteger value in new[] { BigInteger.Zero, BigInteger.One, new BigInteger(2), P - 1 })
        {
            var builder = NewBuilder();
            builder.AddCanonicalBits(Wire(builder, value));
            Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), $"Canonical bits of {value} (< p) must satisfy.");
        }

        //The non-canonical attack: wire = 3, but the bits are overwritten to the
        //pattern of 3 + p (a different 256-bit string recomposing to 3 mod p). The
        //< p chain rejects it — a naive recomposition-only decomposition would not.
        var attacked = NewBuilder();
        int wire = Wire(attacked, 3);
        WireWord bits = attacked.AddCanonicalBits(wire);
        Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(attacked), "The honest decomposition of 3 must satisfy before the attack.");

        InjectBits(attacked, bits, 3 + P);
        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(attacked), "A non-canonical (3 + p) decomposition must be rejected.");
        Assert.ThrowsExactly<InvalidOperationException>(() => Prove(attacked).Dispose());
    }


    [TestMethod]
    public void CanonicalBitsHonestValueProvesAndVerifies()
    {
        //One full-width end-to-end gate: an honest canonical decomposition proves and
        //verifies, confirming the evaluator's satisfaction agrees with the prover at
        //256 bits (slow — the O(n²) encoder over ~512 quadratics).
        BigInteger value = BigInteger.Parse(
            "123456789abcdef0fedcba98765432100123456789abcdef", System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);

        var builder = NewBuilder();
        builder.AddCanonicalBits(Wire(builder, value));

        using LigeroProof proof = Prove(builder);
        Assert.IsTrue(Verify(builder, proof), "An honest full-width canonical-bits proof must verify.");
    }


    [TestMethod]
    public void RangeBelowAcceptsBelowOrderAndRejectsAtOrAbove()
    {
        //AddRangeBelow over the curve order n, driven by honest wire values. Below n
        //satisfies; at or above n (including p − 1, which is ≥ n) is rejected.
        foreach(BigInteger value in new[] { BigInteger.Zero, BigInteger.One, N - 1 })
        {
            var builder = NewBuilder();
            builder.AddRangeBelow(Wire(builder, value), NBytes);
            Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), $"{value} < n must satisfy AddRangeBelow.");
        }

        foreach(BigInteger value in new[] { N, N + 5, P - 1 })
        {
            var builder = NewBuilder();
            builder.AddRangeBelow(Wire(builder, value), NBytes);
            Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(builder), $"{value} ≥ n must violate AddRangeBelow.");
        }
    }


    [TestMethod]
    public void RangeBelowRejectsNonCanonicalRepresentative()
    {
        //The scalar-swap analog: wire = 5 (< n), but the bits are overwritten to the
        //pattern of 5 + p. The canonical-bits < p chain rejects it, so a malicious
        //prover cannot pass off 5 + p (which would feed a different integer into a
        //ladder) as the value 5.
        var builder = NewBuilder();
        int wire = Wire(builder, 5);
        WireWord bits = builder.AddRangeBelow(wire, NBytes);
        Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), "The honest decomposition of 5 must satisfy before the attack.");

        InjectBits(builder, bits, 5 + P);
        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(builder), "A non-canonical (5 + p) representative must be rejected.");
        Assert.ThrowsExactly<InvalidOperationException>(() => Prove(builder).Dispose());
    }


    [TestMethod]
    public void AtLeastAcceptsValuesAtOrAboveThresholdAndRejectsBelow()
    {
        //age ≥ threshold via a bounded difference (8 bits, the age-over-threshold
        //predicate the Longfellow credential proof uses).
        byte[] threshold = Bytes(18);

        foreach(BigInteger value in new[] { new BigInteger(18), new BigInteger(19), new BigInteger(34), new BigInteger(18 + 255) })
        {
            var builder = NewBuilder();
            builder.AddAtLeast(Wire(builder, value), threshold, 8);
            Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), $"{value} ≥ 18 must satisfy AddAtLeast.");
        }

        //Below the threshold: the difference wraps to a large field element.
        foreach(BigInteger value in new[] { BigInteger.Zero, new BigInteger(16), new BigInteger(17) })
        {
            var builder = NewBuilder();
            builder.AddAtLeast(Wire(builder, value), threshold, 8);
            Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(builder), $"{value} < 18 must violate AddAtLeast.");
        }

        //Beyond threshold + 2^8: the difference no longer fits the bounded width.
        var tooFar = NewBuilder();
        tooFar.AddAtLeast(Wire(tooFar, 18 + 256), threshold, 8);
        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(tooFar), "A value beyond threshold + 2^bits must not satisfy the bounded predicate.");
    }


    private static int[] BitsOf(LigeroConstraintSystemBuilder builder, BigInteger value, int bitCount)
    {
        //Literal boolean bit wires of value (least-significant first), each pinned by
        //AddBit — the bits ARE the input, with no wire-decomposition indirection.
        int[] bits = new int[bitCount];
        Span<byte> bit = stackalloc byte[ScalarSize];
        for(int i = 0; i < bitCount; i++)
        {
            bit.Clear();
            bit[ScalarSize - 1] = (byte)(((value >> i) & BigInteger.One) == BigInteger.One ? 1 : 0);
            bits[i] = builder.AddBit(bit);
        }

        return bits;
    }


    private static void InjectBits(LigeroConstraintSystemBuilder builder, ReadOnlySpan<int> bitsLeastSignificantFirst, BigInteger value)
    {
        Span<byte> bit = stackalloc byte[ScalarSize];
        for(int i = 0; i < bitsLeastSignificantFirst.Length; i++)
        {
            bit.Clear();
            bit[ScalarSize - 1] = (byte)(((value >> i) & BigInteger.One) == BigInteger.One ? 1 : 0);
            builder.SetWireForTesting(bitsLeastSignificantFirst[i], bit);
        }
    }


    private static int Wire(LigeroConstraintSystemBuilder builder, BigInteger value) => builder.AddWire(Bytes(value));


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
