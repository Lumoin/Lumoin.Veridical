using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Gates for the bit-plucker gadget (<see cref="LongfellowBitPlucker"/>) and its witness-side
/// counterpart (<see cref="LongfellowBitPluckerEncoder"/>), a faithful port of
/// google/longfellow-zk's <c>bit_plucker_test.cc</c>: the encode-then-pluck round trip, a
/// non-plucker-point input's bitness-assertion latch, and the 32-bit packing helpers
/// (<c>mkpacked_v32</c>/<c>unpack_v32</c>, and the generic <c>pack</c>). The reference's
/// <c>BitPlucker.EltMuxer</c> and <c>BitPlucker.EltMuxer9</c> tests are out of scope: <c>EltMuxer</c>
/// is a separate gadget this port has not yet built.
/// </summary>
/// <remarks>
/// <para>
/// The reference's <c>test_plucker&lt;LOGN, Field&gt;()</c> sweeps <c>LOGN = 1..5</c> over both a
/// prime field and <c>GF2_128&lt;&gt;</c>; this port sweeps <c>LOGN = 1..4</c>: each output bit is
/// its own independently interpolated polynomial, so the construction and evaluation shape does not
/// change with <c>LOGN</c>, and the narrower sweep still exercises every point count from a single
/// point pair up through sixteen.
/// </para>
/// <para>
/// <c>Pluck</c>'s per-bit <see cref="LongfellowLogic.AssertIsBit(int)"/> has no dedicated reference
/// test of its own failure path, so this port adds one: evaluating the plucker's interpolated
/// polynomials at a field element that is not one of the <c>LOGN</c>-width plucker points generically
/// yields a value outside <c>{0, 1}</c>, latching a failure on a non-panicking backend.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowBitPluckerTests
{
    /// <summary>
    /// The reference sweeps LOGN = 1..5; each output bit's polynomial is interpolated and evaluated by
    /// the same fixed procedure regardless of LOGN, so 1..4 still exercises every point count from a
    /// single pair up through sixteen without re-covering a shape the reference itself repeats.
    /// </summary>
    private const int MinLogPointCount = 1;

    /// <summary>The upper bound of the LOGN sweep; see <see cref="MinLogPointCount"/> for why the range is narrowed from the reference's 1..5.</summary>
    private const int MaxLogPointCount = 4;

    /// <summary>
    /// The task's own example width for the non-point latch gate and the packing gates below; chosen
    /// because it is the width <see cref="PackedV32ElementCountAtLogPointCountTwo"/> below is defined
    /// against.
    /// </summary>
    private const int PackingLogPointCount = 2;

    /// <summary>The reference's <c>kNv32Elts</c> formula at LOGN = 2: <c>ceil(32 / 2) = 16</c>.</summary>
    private const int PackedV32ElementCountAtLogPointCountTwo = 16;

    /// <summary>The P-256 base field's modulus-minus-one, canonical big-endian, used to construct <see cref="Fp256Field"/>.</summary>
    private static ReadOnlyMemory<byte> Fp256MinusOne { get; } = BuildFp256MinusOne();

    /// <summary>The GF(2^128) field bundle gated over by the GF(2^128) tests.</summary>
    private static LongfellowLogicFieldOperations Gf2128Field { get; } = LongfellowLogicFieldOperations.CreateGf2128(
        Gf2k128Backend.GetAdd(),
        Gf2k128Backend.GetSubtract(),
        Gf2k128Backend.GetMultiply(),
        Gf2k128Backend.GetInvert());

    /// <summary>The P-256 base field bundle gated over by the Fp256 tests.</summary>
    private static LongfellowLogicFieldOperations Fp256Field { get; } = LongfellowLogicFieldOperations.CreateFp256(
        P256BaseFieldReference.GetAdd(),
        P256BaseFieldReference.GetSubtract(),
        P256BaseFieldReference.GetMultiply(),
        P256BaseFieldReference.GetInvert(),
        Fp256MinusOne);


    /// <summary>Pins that encode-then-pluck round-trips to the original bits across every swept LOGN over GF(2^128).</summary>
    [TestMethod]
    public void EncodeThenPluckRoundTripsToTheOriginalBitsOverGf2128()
    {
        AssertEncodePluckRoundTrip(Gf2128Field);
    }


    /// <summary>Pins that encode-then-pluck round-trips to the original bits across every swept LOGN over the P-256 base field.</summary>
    [TestMethod]
    public void EncodeThenPluckRoundTripsToTheOriginalBitsOverFp256()
    {
        AssertEncodePluckRoundTrip(Fp256Field);
    }


    /// <summary>Pins that plucking a non-plucker-point value latches a bitness-assertion failure over GF(2^128).</summary>
    [TestMethod]
    public void PluckOfANonPluckerPointLatchesTheBitnessAssertionOverGf2128()
    {
        AssertNonPluckerPointLatchesBitnessAssertion(Gf2128Field);
    }


    /// <summary>Pins that plucking a non-plucker-point value latches a bitness-assertion failure over the P-256 base field.</summary>
    [TestMethod]
    public void PluckOfANonPluckerPointLatchesTheBitnessAssertionOverFp256()
    {
        AssertNonPluckerPointLatchesBitnessAssertion(Fp256Field);
    }


    /// <summary>Pins that both the encoder's and the plucker's PackedV32ElementCount match the reference's kNv32Elts formula at LOGN = 2.</summary>
    [TestMethod]
    public void PackedV32ElementCountAtLogPointCountTwoMatchesTheReferenceKNv32EltsFormula()
    {
        var logic = new LongfellowLogic(new LongfellowEvaluationLogicBackend(Gf2128Field), Gf2128Field);
        var encoder = new LongfellowBitPluckerEncoder(Gf2128Field, PackingLogPointCount);
        var plucker = new LongfellowBitPlucker(logic, PackingLogPointCount);

        Assert.AreEqual(PackedV32ElementCountAtLogPointCountTwo, encoder.PackedV32ElementCount, "The encoder's PackedV32ElementCount must match the reference's kNv32Elts formula.");
        Assert.AreEqual(PackedV32ElementCountAtLogPointCountTwo, plucker.PackedV32ElementCount, "The plucker's PackedV32ElementCount must match the reference's kNv32Elts formula.");
    }


    /// <summary>Pins that MakePackedV32 round-trips through UnpackV32 at LOGN = 2 over GF(2^128).</summary>
    [TestMethod]
    public void MakePackedV32RoundTripsThroughUnpackAtLogPointCountTwoOverGf2128()
    {
        var logic = new LongfellowLogic(new LongfellowEvaluationLogicBackend(Gf2128Field), Gf2128Field);
        var encoder = new LongfellowBitPluckerEncoder(Gf2128Field, PackingLogPointCount);
        var plucker = new LongfellowBitPlucker(logic, PackingLogPointCount);

        (uint value, _) = BuildPackingTestVector();
        ReadOnlyMemory<byte>[] packed = encoder.MakePackedV32(value);

        Assert.HasCount(PackedV32ElementCountAtLogPointCountTwo, packed, "MakePackedV32 must produce PackedV32ElementCount elements.");

        var packedWires = new int[packed.Length];
        for(int i = 0; i < packed.Length; i++)
        {
            packedWires[i] = logic.Backend.Constant(packed[i].Span);
        }

        LongfellowBitWire[] unpacked = plucker.UnpackV32(packedWires);
        Assert.HasCount(LongfellowLogic.BitWidth32, unpacked, "UnpackV32 must produce exactly 32 bits.");

        for(int i = 0; i < LongfellowLogic.BitWidth32; i++)
        {
            int expectedBit = (int)((value >> i) & 1u);
            byte[] expected = (expectedBit == 0 ? Gf2128Field.Compiler.Zero : Gf2128Field.Compiler.One).ToArray();

            Assert.IsTrue(EvaluatedBytes(logic, logic.Eval(unpacked[i])).AsSpan().SequenceEqual(expected), $"UnpackV32 bit {i} must round-trip the packed value's bit {i}.");
        }
    }


    /// <summary>Pins that the encoder's generic Pack agrees with MakePackedV32 on the same bit pattern over GF(2^128).</summary>
    [TestMethod]
    public void EncoderPackAgreesWithMakePackedV32OnTheSameBitPatternOverGf2128()
    {
        var encoder = new LongfellowBitPluckerEncoder(Gf2128Field, PackingLogPointCount);

        (uint value, byte[] bitBytes) = BuildPackingTestVector();
        ReadOnlyMemory<byte>[] fromValue = encoder.MakePackedV32(value);
        ReadOnlyMemory<byte>[] fromBits = encoder.Pack(bitBytes, LongfellowLogic.BitWidth32, PackedV32ElementCountAtLogPointCountTwo);

        Assert.HasCount(fromValue.Length, fromBits, "Pack and MakePackedV32 must produce the same element count for the same bit pattern.");
        for(int i = 0; i < fromValue.Length; i++)
        {
            Assert.IsTrue(fromValue[i].Span.SequenceEqual(fromBits[i].Span), $"Pack and MakePackedV32 must agree on packed element {i}.");
        }
    }


    /// <summary>Pins that both the powers-and-dot-product polynomial evaluation and the parallel Horner evaluation agree with a hand-computed closed-form value.</summary>
    [TestMethod]
    public void PolynomialEvaluationAndParallelHornerAgreeWithTheClosedFormValue()
    {
        var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        var polynomial = new LongfellowCircuitPolynomial(backend);

        //P(x) = 3 + x + 4x^2 + x^3 + 5x^4 at x = 7: 3 + 7 + 196 + 343 + 12005 = 12554. Five
        //coefficients exercise the parallel Horner's ceiling halving over an odd count.
        ReadOnlyMemory<byte>[] coefficients =
        [
            Fp256Field.OfScalar(3), Fp256Field.OfScalar(1), Fp256Field.OfScalar(4), Fp256Field.OfScalar(1), Fp256Field.OfScalar(5),
        ];
        const ulong EvaluationPoint = 7;
        const ulong ExpectedValue = 12554;

        int x = backend.Constant(Fp256Field.OfScalar(EvaluationPoint).Span);
        int dotProduct = polynomial.Evaluate(coefficients, x);
        int horner = polynomial.EvaluateHorner(coefficients, x);

        byte[] expected = Fp256Field.OfScalar(ExpectedValue).ToArray();
        Assert.IsTrue(backend.ElementAt(dotProduct).Span.SequenceEqual(expected), "The powers-and-dot-product evaluation must match the closed-form value.");
        Assert.IsTrue(backend.ElementAt(horner).Span.SequenceEqual(expected), "The parallel Horner evaluation must match the closed-form value.");
    }


    /// <summary>Pins that both the plucker and the encoder reject a point-count exponent beyond the reference's eight-bit maximum.</summary>
    [TestMethod]
    public void ThePluckerAndEncoderRejectAPointCountBeyondTheReferenceMaximum()
    {
        //The reference instantiates at most eight packed bits per element; the constructors cap
        //there to keep a hostile width from driving an unbounded interpolation.
        const int BeyondMaxLogPointCount = 9;

        var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        var logic = new LongfellowLogic(backend, Fp256Field);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new LongfellowBitPlucker(logic, BeyondMaxLogPointCount), "The plucker must reject a point-count exponent beyond eight.");
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => new LongfellowBitPluckerEncoder(Fp256Field, BeyondMaxLogPointCount), "The encoder must reject a point-count exponent beyond eight.");
    }


    /// <summary>Pins the kernel-compiled plucker circuit's telemetry against the reference compiler's published pluck-size statistics across every swept LOGN.</summary>
    [TestMethod]
    public void TheCompiledPluckerTelemetryMatchesTheReferenceCompiler()
    {
        //The reference's pluck-size figures at the pinned commit, regenerated by running
        //BitPlucker.PluckSizePrimeField in the longfellow-ref Docker oracle (they also agree with
        //bit_plucker.h's header comment): per LOGN 1..4, depth, wires, out, ovh, t, cse and notn.
        //These pin the interpolation, the powers-of-x association, the dot-product fold, the bitness
        //assertions and the backend subtraction's dead constant node against the reference compiler.
        int[][] expected =
        [
            [3, 6, 2, 2, 6, 0, 9],
            [4, 14, 4, 5, 18, 5, 19],
            [5, 25, 6, 8, 38, 23, 40],
            [6, 40, 8, 11, 74, 73, 87],
        ];

        //Every pluck circuit reads a single packed element beside the constant-one wire.
        const int PluckInputCount = 2;
        const int SingleCopy = 1;

        for(int logPointCount = MinLogPointCount; logPointCount <= MaxLogPointCount; logPointCount++)
        {
            var builder = new LongfellowQuadCircuitBuilder(Fp256Field.Compiler);
            var backend = new LongfellowCompileLogicBackend(Fp256Field, builder);
            var logic = new LongfellowLogic(backend, Fp256Field);
            var plucker = new LongfellowBitPlucker(logic, logPointCount);

            int element = logic.InputElement();
            LongfellowBitWire[] bits = plucker.Pluck(element);
            for(int k = 0; k < logPointCount; k++)
            {
                logic.Output(bits[k], k);
            }

            _ = builder.MakeCircuit(SingleCopy, Sha256FiatShamirBackend.GetIncrementalFactory());

            int[] pins = expected[logPointCount - MinLogPointCount];
            Assert.AreEqual(pins[0], builder.DepthUpperBound, $"pluck[{logPointCount}]'s depth must match the reference compiler's.");
            Assert.AreEqual(pins[1], builder.WireCount, $"pluck[{logPointCount}]'s wire count must match the reference compiler's.");
            Assert.AreEqual(PluckInputCount, builder.InputCount, $"pluck[{logPointCount}]'s input count must match the reference compiler's.");
            Assert.AreEqual(pins[2], builder.OutputCount, $"pluck[{logPointCount}]'s output count must match the reference compiler's.");
            Assert.AreEqual(pins[3], builder.CopyWireOverheadCount, $"pluck[{logPointCount}]'s copy overhead must match the reference compiler's.");
            Assert.AreEqual(pins[4], builder.QuadTermCount, $"pluck[{logPointCount}]'s quad-term count must match the reference compiler's.");
            Assert.AreEqual(pins[5], builder.EliminatedSubexpressionCount, $"pluck[{logPointCount}]'s eliminated-subexpression count must match the reference compiler's.");
            Assert.AreEqual(pins[6], builder.NotNeededCount, $"pluck[{logPointCount}]'s not-needed count must match the reference compiler's.");
        }
    }


    /// <summary>Runs the reference's <c>test_plucker</c> encode-then-pluck round trip over every swept <c>LOGN</c>, over one field bundle.</summary>
    /// <param name="field">The field bundle to gate over.</param>
    private static void AssertEncodePluckRoundTrip(LongfellowLogicFieldOperations field)
    {
        for(int logPointCount = MinLogPointCount; logPointCount <= MaxLogPointCount; logPointCount++)
        {
            var backend = new LongfellowEvaluationLogicBackend(field);
            var logic = new LongfellowLogic(backend, field);
            var encoder = new LongfellowBitPluckerEncoder(field, logPointCount);
            var plucker = new LongfellowBitPlucker(logic, logPointCount);

            int pointCount = 1 << logPointCount;
            for(int i = 0; i < pointCount; i++)
            {
                int wire = backend.Constant(encoder.Encode(i).Span);
                LongfellowBitWire[] bits = plucker.Pluck(wire);

                for(int k = 0; k < logPointCount; k++)
                {
                    int expectedBit = (i >> k) & 1;
                    byte[] expected = (expectedBit == 0 ? field.Compiler.Zero : field.Compiler.One).ToArray();

                    Assert.IsTrue(EvaluatedBytes(logic, logic.Eval(bits[k])).AsSpan().SequenceEqual(expected), $"Pluck bit {k} of encode({i}) at logPointCount={logPointCount} must equal bit {k} of {i}.");
                }
            }
        }
    }


    /// <summary>Asserts that plucking a field element outside the plucker's known point set latches a bitness-assertion failure, over one field bundle.</summary>
    /// <param name="field">The field bundle to gate over.</param>
    private static void AssertNonPluckerPointLatchesBitnessAssertion(LongfellowLogicFieldOperations field)
    {
        int pointCount = 1 << PackingLogPointCount;

        var backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, field);
        var plucker = new LongfellowBitPlucker(logic, PackingLogPointCount);

        //OfScalar(pointCount) is not one of the plucker's pointCount interpolation points (those
        //encode 2*i - (pointCount - 1) for i < pointCount), so pluck's per-bit bitness assertion must
        //latch a failure on at least one output bit.
        int wire = backend.Constant(field.OfScalar((ulong)pointCount).Span);
        _ = plucker.Pluck(wire);

        Assert.IsTrue(backend.AssertionFailed, "Plucking a non-plucker-point value must latch a bitness assertion failure.");
    }


    /// <summary>
    /// Builds a deterministic 32-bit test vector for the packing gates: 16 groups of
    /// <see cref="PackingLogPointCount"/> bits each, the group value cycling <c>0, 1, 2, 3, 0, 1, 2,
    /// 3, ...</c> across the groups so every possible group value is exercised.
    /// </summary>
    /// <returns>The packed value, and the same bits expanded one-byte-per-bit least significant first.</returns>
    private static (uint Value, byte[] BitBytes) BuildPackingTestVector()
    {
        var bitBytes = new byte[LongfellowLogic.BitWidth32];
        uint value = 0;
        int groupValueCount = 1 << PackingLogPointCount;

        for(int i = 0; i < LongfellowLogic.BitWidth32; i++)
        {
            int group = i / PackingLogPointCount;
            int bitInGroup = i % PackingLogPointCount;
            int groupValue = group % groupValueCount;
            int bit = (groupValue >> bitInGroup) & 1;

            bitBytes[i] = (byte)bit;
            if(bit != 0)
            {
                value |= 1u << i;
            }
        }

        return (value, bitBytes);
    }


    /// <summary>Reads a wire's canonical bytes off its evaluating backend.</summary>
    /// <param name="logic">The gadget layer the wire was built over.</param>
    /// <param name="wire">The wire to read.</param>
    /// <returns>The wire's canonical bytes.</returns>
    private static byte[] EvaluatedBytes(LongfellowLogic logic, int wire) => ((LongfellowEvaluationLogicBackend)logic.Backend).ElementAt(wire).ToArray();


    /// <summary>Builds the P-256 base field's modulus-minus-one, canonical big-endian, for <see cref="LongfellowLogicFieldOperations.CreateFp256"/>.</summary>
    /// <returns>The canonical <c>p - 1</c>.</returns>
    private static byte[] BuildFp256MinusOne()
    {
        byte[] canonical = new byte[Scalar.SizeBytes];
        byte[] bigEndian = (P256BaseFieldReference.FieldOrder - 1).ToByteArray(isUnsigned: true, isBigEndian: true);
        bigEndian.CopyTo(canonical.AsSpan(Scalar.SizeBytes - bigEndian.Length));

        return canonical;
    }
}
