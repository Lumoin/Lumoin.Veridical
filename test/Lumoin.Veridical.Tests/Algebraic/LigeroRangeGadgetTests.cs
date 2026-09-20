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

    /// <summary>The P-256 base-field prime, the modulus the canonical-bits gadget bounds decompositions below.</summary>
    private static BigInteger P { get; } = P256BigIntegerG1Reference.BaseFieldPrime;

    /// <summary>The P-256 scalar-field order (curve order n), the bound the range gadgets under test check against.</summary>
    private static BigInteger N { get; } = WellKnownCurves.GetScalarFieldOrder(CurveParameterSet.P256);

    /// <summary>The curve order <see cref="N"/> as canonical big-endian bytes, the constant operand the comparator gadgets take.</summary>
    private static byte[] NBytes { get; } = Bytes(N);

    /// <summary>The deterministic transcript seed these gates share between proving and verifying.</summary>
    private static byte[] TranscriptSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.range.v1");

    /// <summary>The deterministic seed for this class's reproducible Fp256 randomness source.</summary>
    private static byte[] RandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.longfellow.range.rng.v1");

    /// <summary>The BLAKE3 Fiat-Shamir hash delegate driving both the prover's and verifier's transcripts.</summary>
    private static FiatShamirHashDelegate Hash { get; } = Blake3FiatShamirBackend.GetHash();

    /// <summary>The BLAKE3 Fiat-Shamir squeeze delegate drawing challenges from the transcript.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = Blake3FiatShamirBackend.GetSqueeze();

    /// <summary>The Merkle two-to-one compression delegate, backed by <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;


    /// <summary>Verifies that the less-than-constant comparator over an 8-bit literal accepts values strictly below 200 and rejects values at or above it.</summary>
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


    /// <summary>Verifies that the less-than-constant comparator agrees with the prover: a below-bound instance proves and verifies, while an at-bound instance is unprovable because the prover refuses an unsatisfiable witness.</summary>
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


    /// <summary>Verifies that the full 256-bit less-than-constant comparator against the curve order n accepts values below n and rejects values at or above it, including alias-band values (n ≤ B &lt; p) a naive mod-p check would miss.</summary>
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


    /// <summary>Verifies that canonical-bits decomposition accepts honest values below p and rejects a non-canonical decomposition whose bits are overwritten to a different 256-bit string (value + p) that recomposes to the same residue.</summary>
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


    /// <summary>Verifies that an honest full-width canonical-bits decomposition proves and verifies end-to-end, confirming the evaluator's satisfaction agrees with the prover at 256 bits.</summary>
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


    /// <summary>Verifies that AddRangeBelow accepts values below the curve order n and rejects values at or above it, including p - 1.</summary>
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


    /// <summary>Verifies that AddRangeBelow rejects a non-canonical representative whose bits are overwritten to the pattern of value + p, so a malicious prover cannot smuggle a different integer through the ladder.</summary>
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


    /// <summary>Verifies that AddAtLeast accepts values at or above the threshold within the bounded width, rejects values below it, and rejects a value far enough beyond the threshold that the difference no longer fits the bounded width.</summary>
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


    /// <summary>Builds literal boolean bit wires for <paramref name="value"/> (least-significant first), each pinned by AddBit, so the bits are the input directly with no wire-decomposition indirection.</summary>
    private static int[] BitsOf(LigeroConstraintSystemBuilder builder, BigInteger value, int bitCount)
    {
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


    /// <summary>Overwrites the given bit wires in place with the bit pattern of <paramref name="value"/>, used to simulate a malicious prover substituting a different (typically non-canonical) decomposition after an honest one was built.</summary>
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


    /// <summary>Adds a wire holding <paramref name="value"/> as its canonical big-endian scalar.</summary>
    private static int Wire(LigeroConstraintSystemBuilder builder, BigInteger value) => builder.AddWire(Bytes(value));


    /// <summary>Returns a value as a canonical big-endian scalar of <see cref="ScalarSize"/> bytes.</summary>
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
