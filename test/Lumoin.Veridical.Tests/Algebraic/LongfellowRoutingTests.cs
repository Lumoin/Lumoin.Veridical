using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Gates for the barrel-shifter gadget (<see cref="LongfellowRouting"/>), the evaluation-half port of
/// google/longfellow-zk's <c>routing_test.cc</c>'s <c>TEST(Routing, Simple)</c>: shift and unshift
/// semantics swept across <c>logn</c>, the source/destination lane counts, the shift amount and the
/// per-round unroll budget, over all three lane kinds (single-bit lanes, element-wire lanes, and
/// three-bit-vector lanes) in one pass per swept combination, exactly as the reference's
/// <c>one_test</c> exercises them.
/// </summary>
/// <remarks>
/// <para>
/// The reference sweeps <c>n</c>/<c>k</c> up to 16, <c>shift</c> up to 16 and <c>unroll</c> up to 8
/// over a native fixed-width field, cheap enough to run exhaustively at every <c>logn</c> from 1
/// through 5 (plus a second, sparser pass up to <c>logn</c> 8). This port narrows every bound
/// (<see cref="MaxLaneCount"/>, <see cref="MaxShift"/>, <see cref="MaxUnroll"/>) to keep the sweep
/// tractable over the BigInteger-backed <see cref="P256BaseFieldReference"/> test oracle, while still
/// exercising every round-schedule shape the reference's <c>ceildiv</c> equalization produces across
/// <c>logn</c> 1 through 5. The reference's own randomized default values (the default bit XORs every
/// swept parameter together; the element/vector defaults are a shared literal) are replaced here by
/// fixed defaults, since a fixed default already exercises the "outside the source" branch identically
/// regardless of which parameter combination is running.
/// </para>
/// <para>
/// Both directions size their want/got arrays to <see cref="MaxLaneCount"/>'s <c>k</c>, matching the
/// reference's own <c>lwant(k)</c>/<c>lgot(k)</c> (and the element/vector equivalents): <c>n</c> is
/// always the source array's length and <c>k</c> is always the destination array's length, for both
/// <see cref="LongfellowRouting.Shift(LongfellowBitWire[], int[], int[], int, int)"/> and
/// <see cref="LongfellowRouting.Unshift(LongfellowBitWire[], int[], int[], int, int)"/>.
/// </para>
/// <para>
/// The reference's separate <c>EltCircuitSize</c>/<c>BitCircuitSize</c> tests are out of scope here —
/// they drive <c>QuadCircuit</c>/<c>CompilerBackend</c> telemetry, not the evaluation-backend
/// semantics this file gates.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowRoutingTests
{
    /// <summary>The sweep's lowest <c>logn</c>: a single amount bit, the narrowest possible round schedule.</summary>
    private const int MinLogAmountBitWidth = 1;

    /// <summary>The sweep's highest <c>logn</c>, narrowed from the reference's 8 (in its sparse second pass) to keep the exhaustive BigInteger-backed sweep tractable while still covering every unroll/round-count shape at up to five amount bits.</summary>
    private const int MaxLogAmountBitWidth = 5;

    /// <summary>The sweep's lowest source/destination lane count.</summary>
    private const int MinLaneCount = 1;

    /// <summary>The sweep's highest source/destination lane count, narrowed from the reference's 16; halved again from an initial 12 once the full sweep measured about 24 seconds locally, over the ~20-second budget.</summary>
    private const int MaxLaneCount = 6;

    /// <summary>The sweep's lowest shift amount.</summary>
    private const int MinShift = 0;

    /// <summary>The sweep's highest shift amount, narrowed from the reference's 16; halved again alongside <see cref="MaxLaneCount"/> for the same wall-clock reason.</summary>
    private const int MaxShift = 6;

    /// <summary>The sweep's lowest per-round unroll budget.</summary>
    private const int MinUnroll = 1;

    /// <summary>The sweep's highest per-round unroll budget, narrowed from the reference's 8: still forces multi-round schedules at every swept <c>logn</c> above two.</summary>
    private const int MaxUnroll = 4;

    /// <summary>The bit-vector lane kind's width (the reference's <c>bv</c> alias at <c>W = 3</c>).</summary>
    private const int VectorLaneWidth = 3;

    /// <summary>The mask selecting the low <see cref="VectorLaneWidth"/> bits of a source index's offset value.</summary>
    private const ulong VectorLaneMask = (1UL << VectorLaneWidth) - 1;

    /// <summary>The offset added to a lane index to build that lane's element/vector source value (the reference's <c>i + 42</c>).</summary>
    private const ulong LaneValueOffset = 42;

    /// <summary>The fixed single-bit default value read wherever a lane falls outside the source.</summary>
    private const int DefaultBitValue = 1;

    /// <summary>The fixed element-wire default value read wherever a lane falls outside the source.</summary>
    private const ulong DefaultElementValue = 12345;

    /// <summary>The fixed bit-vector default value read wherever a lane falls outside the source.</summary>
    private const ulong DefaultVectorValue = 5;

    /// <summary>The P-256 base field's modulus-minus-one, canonical big-endian, used to construct <see cref="Fp256Field"/>.</summary>
    private static ReadOnlyMemory<byte> Fp256MinusOne { get; } = BuildFp256MinusOne();

    /// <summary>The P-256 base field bundle gated over by every test in this class.</summary>
    private static LongfellowLogicFieldOperations Fp256Field { get; } = LongfellowLogicFieldOperations.CreateFp256(
        P256BaseFieldReference.GetAdd(),
        P256BaseFieldReference.GetSubtract(),
        P256BaseFieldReference.GetMultiply(),
        P256BaseFieldReference.GetInvert(),
        Fp256MinusOne);


    /// <summary>Pins the reference's <c>one_test</c> shift/unshift semantics across the bounded sweep, over all three lane kinds.</summary>
    [TestMethod]
    public void TheSweepMatchesTheReferenceShiftAndUnshiftSemantics()
    {
        for(int logn = MinLogAmountBitWidth; logn <= MaxLogAmountBitWidth; logn++)
        {
            for(int n = MinLaneCount; n <= MaxLaneCount; n++)
            {
                for(int k = MinLaneCount; k <= MaxLaneCount; k++)
                {
                    for(int shift = MinShift; shift <= MaxShift; shift++)
                    {
                        for(int unroll = MinUnroll; unroll <= MaxUnroll; unroll++)
                        {
                            AssertOneCombination(logn, n, k, shift, unroll);
                        }
                    }
                }
            }
        }
    }


    /// <summary>Runs one swept <c>(logn, n, k, shift, unroll)</c> combination through both <c>Shift</c> and <c>Unshift</c>, over all three lane kinds, on a fresh backend so the sweep's total interned-wire count never grows across combinations.</summary>
    /// <param name="logn">The amount's bit width.</param>
    /// <param name="n">The source lane count.</param>
    /// <param name="k">The destination lane count.</param>
    /// <param name="shift">The shift amount, before reduction modulo <c>2^logn</c>.</param>
    /// <param name="unroll">The per-round amount-bit budget.</param>
    private static void AssertOneCombination(int logn, int n, int k, int shift, int unroll)
    {
        var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        var logic = new LongfellowLogic(backend, Fp256Field);
        var routing = new LongfellowRouting(logic);

        LongfellowBitWire bitDefault = logic.Bit(DefaultBitValue);
        int elementDefault = backend.Constant(Fp256Field.OfScalar(DefaultElementValue).Span);
        LongfellowBitWire[] vectorDefault = logic.BitVector(VectorLaneWidth, DefaultVectorValue);

        var bitSource = new LongfellowBitWire[n];
        var elementSource = new int[n];
        var vectorSource = new LongfellowBitWire[n][];
        for(int i = 0; i < n; i++)
        {
            bitSource[i] = logic.Bit((i ^ (i >> 2) ^ (i >> 5)) & 1);
            elementSource[i] = backend.Constant(Fp256Field.OfScalar((ulong)i + LaneValueOffset).Span);
            vectorSource[i] = logic.BitVector(VectorLaneWidth, ((ulong)i + LaneValueOffset) & VectorLaneMask);
        }

        LongfellowBitWire[] amount = logic.BitVector(logn, (ulong)shift);
        int realShift = shift % (1 << logn);

        AssertOneDirection(routing, logic, backend, amount, unroll, unshift: false, n, k, realShift, bitSource, elementSource, vectorSource, bitDefault, elementDefault, vectorDefault, logn, shift);
        AssertOneDirection(routing, logic, backend, amount, unroll, unshift: true, n, k, realShift, bitSource, elementSource, vectorSource, bitDefault, elementDefault, vectorDefault, logn, shift);
    }


    /// <summary>Runs one direction (<c>Shift</c> or <c>Unshift</c>) of one swept combination over all three lane kinds, and asserts every destination lane against the reference's own want formula.</summary>
    /// <param name="routing">The gadget under test.</param>
    /// <param name="logic">The gadget layer the lanes were built over.</param>
    /// <param name="backend">The evaluation backend the lanes were interned on.</param>
    /// <param name="amount">The shift amount's bits.</param>
    /// <param name="unroll">The per-round amount-bit budget.</param>
    /// <param name="unshift">Whether this call runs <c>Unshift</c> rather than <c>Shift</c>.</param>
    /// <param name="n">The source lane count.</param>
    /// <param name="k">The destination lane count.</param>
    /// <param name="realShift">The shift amount already reduced modulo <c>2^logn</c>.</param>
    /// <param name="bitSource">The single-bit source lanes.</param>
    /// <param name="elementSource">The element-wire source lanes.</param>
    /// <param name="vectorSource">The bit-vector source lanes.</param>
    /// <param name="bitDefault">The single-bit default.</param>
    /// <param name="elementDefault">The element-wire default.</param>
    /// <param name="vectorDefault">The bit-vector default.</param>
    /// <param name="logn">The amount's bit width, carried through only for the failure message.</param>
    /// <param name="shift">The unreduced shift amount, carried through only for the failure message.</param>
    private static void AssertOneDirection(
        LongfellowRouting routing,
        LongfellowLogic logic,
        LongfellowEvaluationLogicBackend backend,
        LongfellowBitWire[] amount,
        int unroll,
        bool unshift,
        int n,
        int k,
        int realShift,
        LongfellowBitWire[] bitSource,
        int[] elementSource,
        LongfellowBitWire[][] vectorSource,
        LongfellowBitWire bitDefault,
        int elementDefault,
        LongfellowBitWire[] vectorDefault,
        int logn,
        int shift)
    {
        var bitWant = new LongfellowBitWire[k];
        var elementWant = new int[k];
        var vectorWant = new LongfellowBitWire[k][];
        for(int i = 0; i < k; i++)
        {
            bool inRange = unshift ? i >= realShift && i < n + realShift : i + realShift < n;
            int sourceIndex = unshift ? i - realShift : i + realShift;

            bitWant[i] = inRange ? bitSource[sourceIndex] : bitDefault;
            elementWant[i] = inRange ? elementSource[sourceIndex] : elementDefault;
            vectorWant[i] = inRange ? vectorSource[sourceIndex] : vectorDefault;
        }

        var bitGot = new LongfellowBitWire[k];
        var elementGot = new int[k];
        var vectorGot = new LongfellowBitWire[k][];
        for(int i = 0; i < k; i++)
        {
            vectorGot[i] = new LongfellowBitWire[VectorLaneWidth];
        }

        if(unshift)
        {
            routing.Unshift(amount, bitGot, bitSource, bitDefault, unroll);
            routing.Unshift(amount, elementGot, elementSource, elementDefault, unroll);
            routing.Unshift(amount, vectorGot, vectorSource, vectorDefault, unroll);
        }
        else
        {
            routing.Shift(amount, bitGot, bitSource, bitDefault, unroll);
            routing.Shift(amount, elementGot, elementSource, elementDefault, unroll);
            routing.Shift(amount, vectorGot, vectorSource, vectorDefault, unroll);
        }

        for(int i = 0; i < k; i++)
        {
            string context = $"logn={logn}, n={n}, k={k}, shift={shift}, unroll={unroll}, unshift={unshift}, lane={i}";

            Assert.IsTrue(EvaluatedBytes(logic, logic.Eval(bitGot[i])).AsSpan().SequenceEqual(EvaluatedBytes(logic, logic.Eval(bitWant[i]))), $"Bit lane mismatch at {context}.");
            Assert.IsTrue(backend.ElementAt(elementGot[i]).Span.SequenceEqual(backend.ElementAt(elementWant[i]).Span), $"Element lane mismatch at {context}.");

            for(int w = 0; w < VectorLaneWidth; w++)
            {
                Assert.IsTrue(EvaluatedBytes(logic, logic.Eval(vectorGot[i][w])).AsSpan().SequenceEqual(EvaluatedBytes(logic, logic.Eval(vectorWant[i][w]))), $"Vector lane mismatch at {context}, bit {w}.");
            }
        }
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
