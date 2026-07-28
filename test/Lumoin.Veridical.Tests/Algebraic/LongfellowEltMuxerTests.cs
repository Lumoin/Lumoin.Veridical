using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Gates for the element-array multiplexer gadget (<see cref="LongfellowEltMuxer"/>), the
/// evaluation-half port of google/longfellow-zk's <c>bit_plucker_test.cc</c>'s
/// <c>TEST(BitPlucker, EltMuxer)</c> and <c>TEST(BitPlucker, EltMuxer9)</c>: the eight-entry muxer
/// selecting every table entry across four bit patterns, and the nine-entry-over-an-eight-point
/// muxer that range-checks a digit into <c>{0, ..., 7}</c> without a false positive anywhere else in
/// the field.
/// </summary>
/// <remarks>
/// Both reference tests run over <c>Fp&lt;1&gt;("257")</c>, a tiny prime chosen only so the exhaustive
/// <c>EltMuxer9</c> sweep (every plucker point up to <c>2·257</c>-ish) stays cheap; this port runs the
/// same two tests over <see cref="Fp256Field"/> instead, since every other gate in this batch shares
/// that field bundle and the muxer's construction and evaluation shape does not depend on the field's
/// size.
/// </remarks>
[TestClass]
internal sealed class LongfellowEltMuxerTests
{
    /// <summary>The reference's <c>EltMuxer&lt;Logic, 8&gt;</c> array length and plucker point-set size.</summary>
    private const int TableEntryCount = 8;

    /// <summary>The reference's <c>EltMuxer&lt;Logic, 9, 8&gt;</c> array length: one more than the point-set size, the ECDSA advice-digit range-check shape.</summary>
    private const int NineEntryMuxerElementCount = 9;

    /// <summary>The reference's <c>EltMuxer&lt;Logic, 9, 8&gt;</c> point-set parameter: the muxer interpolates through nine points while keeping the eight-point index encoding.</summary>
    private const int NineEntryMuxerPointSetSize = 8;

    /// <summary>The reference's <c>128 + /*intentional extra element*/ 1</c>: every in-domain point plus one deliberately out-of-domain point.</summary>
    private const int MuxIndexSweepExclusiveUpperBound = 129;

    /// <summary>The reference's <c>arr_z</c>: <c>{0, 1, 1, 1, 1, 1, 1, 1}</c>.</summary>
    private static byte[] ZTable { get; } = [0, 1, 1, 1, 1, 1, 1, 1];

    /// <summary>The reference's <c>arr_e</c>: <c>{0, 1, 0, 1, 0, 1, 0, 1}</c>.</summary>
    private static byte[] ETable { get; } = [0, 1, 0, 1, 0, 1, 0, 1];

    /// <summary>The reference's <c>arr_r</c>: <c>{0, 0, 1, 1, 0, 0, 1, 1}</c>.</summary>
    private static byte[] RTable { get; } = [0, 0, 1, 1, 0, 0, 1, 1];

    /// <summary>The reference's <c>arr_s</c>: <c>{0, 0, 0, 0, 1, 1, 1, 1}</c>.</summary>
    private static byte[] STable { get; } = [0, 0, 0, 0, 1, 1, 1, 1];

    /// <summary>The reference's <c>arr_v</c>: eight zeros then a one, the digit-range-check table.</summary>
    private static byte[] DigitRangeCheckTable { get; } = [0, 0, 0, 0, 0, 0, 0, 0, 1];

    /// <summary>The P-256 base field's modulus-minus-one, canonical big-endian, used to construct <see cref="Fp256Field"/>.</summary>
    private static ReadOnlyMemory<byte> Fp256MinusOne { get; } = BuildFp256MinusOne();

    /// <summary>The P-256 base field bundle gated over by every test in this class.</summary>
    private static LongfellowLogicFieldOperations Fp256Field { get; } = LongfellowLogicFieldOperations.CreateFp256(
        P256BaseFieldReference.GetAdd(),
        P256BaseFieldReference.GetSubtract(),
        P256BaseFieldReference.GetMultiply(),
        P256BaseFieldReference.GetInvert(),
        Fp256MinusOne);


    /// <summary>Pins that muxing every plucker-point index over each of the four eight-entry tables selects that table's own entry.</summary>
    [TestMethod]
    public void TheMuxerSelectsEveryTableEntry()
    {
        var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        var logic = new LongfellowLogic(backend, Fp256Field);

        AssertMuxerSelectsEveryEntry(backend, logic, ZTable, TableEntryCount);
        AssertMuxerSelectsEveryEntry(backend, logic, ETable, TableEntryCount);
        AssertMuxerSelectsEveryEntry(backend, logic, RTable, TableEntryCount);
        AssertMuxerSelectsEveryEntry(backend, logic, STable, TableEntryCount);
    }


    /// <summary>Pins that the nine-entry-over-an-eight-point muxer selects the genuine entry for every in-domain index, and yields a nonzero (never a false-positive digit) value everywhere else in the sweep.</summary>
    [TestMethod]
    public void TheNineEntryMuxerRangeChecksTheDigitDomain()
    {
        var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        var logic = new LongfellowLogic(backend, Fp256Field);

        int[] wires = BuildTableWires(backend, Fp256Field, DigitRangeCheckTable);
        var muxer = new LongfellowEltMuxer(logic, wires, NineEntryMuxerPointSetSize);

        for(int i = 0; i < MuxIndexSweepExclusiveUpperBound; i++)
        {
            int index = backend.Constant(LongfellowBitPlucker.PluckerPoint(Fp256Field, NineEntryMuxerPointSetSize, i).Span);
            int selected = muxer.Mux(index);

            if(i < NineEntryMuxerElementCount)
            {
                Assert.IsTrue(backend.ElementAt(selected).Span.SequenceEqual(backend.ElementAt(wires[i]).Span), $"Muxing in-domain index {i} must select the array entry it stores.");
            }
            else
            {
                Assert.IsFalse(LongfellowCompilerFieldOperations.ElementIsZero(backend.ElementAt(selected).Span), $"Muxing out-of-domain index {i} must yield a nonzero value, never a false-positive digit match.");
            }
        }
    }


    /// <summary>Asserts that muxing every plucker-point index over one table selects that table's own entry, over one backend/logic pair.</summary>
    /// <param name="backend">The evaluation backend the table and index wires are interned on.</param>
    /// <param name="logic">The gadget layer the muxer builds on.</param>
    /// <param name="table">The table of zero/one entries to mux over.</param>
    /// <param name="pointSetSize">The plucker point-set size the table's own length doubles as.</param>
    private static void AssertMuxerSelectsEveryEntry(LongfellowEvaluationLogicBackend backend, LongfellowLogic logic, byte[] table, int pointSetSize)
    {
        int[] wires = BuildTableWires(backend, Fp256Field, table);
        var muxer = new LongfellowEltMuxer(logic, wires);

        for(int i = 0; i < pointSetSize; i++)
        {
            int index = backend.Constant(LongfellowBitPlucker.PluckerPoint(Fp256Field, pointSetSize, i).Span);
            int selected = muxer.Mux(index);

            Assert.IsTrue(backend.ElementAt(selected).Span.SequenceEqual(backend.ElementAt(wires[i]).Span), $"Muxing table entry {i} must select the array entry it stores.");
        }
    }


    /// <summary>Interns one constant wire per table entry (the reference's <c>L.konst(0)</c>/<c>L.konst(1)</c> array construction).</summary>
    /// <param name="backend">The evaluation backend the constant wires are interned on.</param>
    /// <param name="field">The field-operation bundle supplying the canonical embedding.</param>
    /// <param name="table">The table of zero/one entries.</param>
    /// <returns>The interned wires, one per table entry.</returns>
    private static int[] BuildTableWires(LongfellowEvaluationLogicBackend backend, LongfellowLogicFieldOperations field, byte[] table)
    {
        var wires = new int[table.Length];
        for(int i = 0; i < table.Length; i++)
        {
            wires[i] = backend.Constant(field.OfScalar(table[i]).Span);
        }

        return wires;
    }


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
