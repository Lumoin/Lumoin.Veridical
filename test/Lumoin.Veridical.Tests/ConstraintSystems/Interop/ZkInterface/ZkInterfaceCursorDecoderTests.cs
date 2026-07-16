using Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Tests for the built-in FlatBuffers decoder: the size-prefixed framing /
/// union classification (<see cref="ZkInterfaceCursorDecoder.LocateMessages"/>)
/// and the full decode-into-sink push sequence, both pinned to the vendored
/// example.zkif and its independently-described contents (Fixtures/FIXTURES.md).
/// </summary>
[TestClass]
internal sealed class ZkInterfaceCursorDecoderTests
{
    private const int SizePrefixBytes = 4;


    [TestMethod]
    public void LocateMessagesYieldsHeaderConstraintSystemWitnessInOrder()
    {
        byte[] file = ZkInterfaceExampleFixture.ExampleBytes();

        IReadOnlyList<ZkInterfaceMessageSpan> messages = ZkInterfaceCursorDecoder.LocateMessages(file);

        Assert.HasCount(3, messages, "message count");
        Assert.AreEqual(ZkInterfaceMessageType.CircuitHeader, messages[0].Type, "message 0");
        Assert.AreEqual(ZkInterfaceMessageType.ConstraintSystem, messages[1].Type, "message 1");
        Assert.AreEqual(ZkInterfaceMessageType.Witness, messages[2].Type, "message 2");

        //The located ranges must tile the file exactly: each buffer follows its
        //size prefix, and the last ends at the stream end.
        int runningStart = SizePrefixBytes;
        foreach(ZkInterfaceMessageSpan message in messages)
        {
            Assert.AreEqual(runningStart, message.BufferStart, "message buffer start follows its size prefix");
            runningStart = message.BufferStart + message.BufferLength + SizePrefixBytes;
        }

        Assert.AreEqual(file.Length + SizePrefixBytes, runningStart, "messages tile the whole stream");
    }


    [TestMethod]
    public void LocateMessagesRejectsTruncatedStream()
    {
        byte[] full = ZkInterfaceExampleFixture.ExampleBytes();
        //Cut mid-stream so the final message's declared size overruns.
        byte[] truncated = full.AsSpan(0, full.Length - 8).ToArray();

        Assert.ThrowsExactly<ArgumentException>(() => ZkInterfaceCursorDecoder.LocateMessages(truncated));
    }


    [TestMethod]
    public void LocateMessagesRejectsTrailingBytes()
    {
        byte[] full = ZkInterfaceExampleFixture.ExampleBytes();
        //Append two stray bytes: too few to be a size prefix after the last
        //message, so the loop reports trailing bytes.
        byte[] extended = [.. full, 0, 0];

        Assert.ThrowsExactly<ArgumentException>(() => ZkInterfaceCursorDecoder.LocateMessages(extended));
    }


    [TestMethod]
    public void DecoderPushesExampleHeaderConstraintsAndWitness()
    {
        var sink = new RecordingSink();
        ZkInterfaceCursorDecoder.Decoder(new ReadOnlySequence<byte>(ZkInterfaceExampleFixture.ExampleBytes()), sink, CancellationToken.None);

        //CircuitHeader.
        Assert.AreEqual(6UL, sink.FreeVariableId, "free_variable_id");
        Assert.IsFalse(sink.FieldMaximumSeen, "field_maximum is absent in the toy sample");
        CollectionAssert.AreEqual(new ulong[] { 1, 2, 3 }, sink.InstanceVariableIds, "instance variable ids");
        CollectionAssert.AreEqual(new uint[] { 3, 4, 25 }, sink.InstanceVariableValues, "instance variable values");

        //ConstraintSystem: three constraints, each coefficient the field element 1.
        Assert.AreEqual(3, sink.ConstraintCount, "constraint count");
        foreach(RecordingSink.Term term in sink.Terms)
        {
            Assert.AreEqual(1U, term.Coefficient, $"coefficient (constraint {term.ConstraintIndex}, {term.Matrix})");
        }

        //C0: v1*v1 = v4
        AssertTerms(sink, 0, ZkInterfaceConstraintMatrix.A, [1]);
        AssertTerms(sink, 0, ZkInterfaceConstraintMatrix.B, [1]);
        AssertTerms(sink, 0, ZkInterfaceConstraintMatrix.C, [4]);
        //C2: 1*(v4 + v5) = v3 — B spans two variables.
        AssertTerms(sink, 2, ZkInterfaceConstraintMatrix.A, [0]);
        AssertTerms(sink, 2, ZkInterfaceConstraintMatrix.B, [4, 5]);
        AssertTerms(sink, 2, ZkInterfaceConstraintMatrix.C, [3]);

        //Witness.
        CollectionAssert.AreEqual(new ulong[] { 4, 5 }, sink.WitnessVariableIds, "witness variable ids");
        CollectionAssert.AreEqual(new uint[] { 9, 16 }, sink.WitnessVariableValues, "witness variable values");
    }


    [TestMethod]
    public void DecoderRejectsOffsetAliasingAmplification()
    {
        //A ConstraintSystem whose `constraints` vector holds many offset elements ALL aliased to
        //one BilinearConstraint — whose lc_a shares a single variable_ids vector — decodes
        //O(aliases x ids) terms from a linear-sized message. The decode-work budget, bounded by
        //the source byte length, rejects it before a sink's accumulators can grow: a valid stream's
        //decode work sits far below its byte length, so only aliasing exceeds it. Coefficient width
        //is 1 here, so both budget axes contribute; the zero-width and wide-coefficient siblings
        //isolate the event and scan axes respectively.
        const int constraintAliases = 32;
        const int idsPerConstraint = 32;
        const int coefficientByteWidth = 1;

        AssertAliasedConstraintSystemRejected(constraintAliases, idsPerConstraint, coefficientByteWidth);
    }


    [TestMethod]
    public void DecoderRejectsTermCountAmplificationWithoutCoefficientBytes()
    {
        //Isolates the per-term EVENT charge: zero-width coefficients (an empty `values` vector, so
        //elementSize resolves to 0) make the scan charge contribute nothing, leaving only the
        //per-term event unit to bound the aliased term count. Revert that per-term SpendEvent and the
        //term count slips under budget, so this pins the event axis specifically, not the scan axis.
        const int constraintAliases = 32;
        const int idsPerConstraint = 32;
        const int coefficientByteWidth = 0;

        AssertAliasedConstraintSystemRejected(constraintAliases, idsPerConstraint, coefficientByteWidth);
    }


    [TestMethod]
    public void DecoderRejectsCoefficientScanAmplification()
    {
        //The amplification also travels the per-term BYTE axis: a `constraints` vector aliasing a
        //few offsets onto one BilinearConstraint whose lc_a carries a single id but an over-long
        //(zero-padded) coefficient makes each aliased term re-scan the whole coefficient span in
        //the canonical-scalar writer — O(aliases x coefficient) byte work from a linear message,
        //while the event count stays far under the source length. The budget charges the scanned
        //coefficient bytes, so this is rejected too. Reverting that charge lets the low event count
        //slip through, so this pins the byte axis specifically, not the event axis.
        const int constraintAliases = 8;
        const int idsPerConstraint = 1;
        const int coefficientByteWidth = 64;

        AssertAliasedConstraintSystemRejected(constraintAliases, idsPerConstraint, coefficientByteWidth);
    }


    //Encodes an aliased ConstraintSystem of the given shape and asserts the decode-work budget
    //rejects it with its own message, so a mis-encoded buffer tripping a bounds check would fail
    //this test rather than pass for the wrong reason.
    private static void AssertAliasedConstraintSystemRejected(int constraintAliases, int idsPerConstraint, int coefficientByteWidth)
    {
        int streamLength = AliasedConstraintSystemStreamLength(constraintAliases, idsPerConstraint, coefficientByteWidth);
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(streamLength);
        ReadOnlyMemory<byte> stream = owner.Memory[..streamLength];
        WriteAliasedConstraintSystemStream(owner.Memory.Span[..streamLength], constraintAliases, idsPerConstraint, coefficientByteWidth);

        var sink = new RecordingSink();
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
            ZkInterfaceCursorDecoder.Decoder(new ReadOnlySequence<byte>(stream), sink, CancellationToken.None));

        Assert.Contains("more work than its byte length", exception.Message, "the decode-work budget must be what rejects the aliased stream");
    }


    //The packed stream length for the aliased fixture, mirroring WriteAliasedConstraintSystemStream:
    //the size prefix, the fixed table/vtable framing, and the three data vectors (constraint
    //offsets, variable ids, coefficient values — the values vector holds idsPerConstraint elements
    //of coefficientByteWidth bytes each).
    private static int AliasedConstraintSystemStreamLength(int constraintAliases, int idsPerConstraint, int coefficientByteWidth)
    {
        const int tablesAndVtablesBytes = 69;   //root uoffset + Root/ConstraintSystem/BilinearConstraint/Variables tables and their vtables.
        int constraintsVectorBytes = 4 + (4 * constraintAliases);
        int idsVectorBytes = 4 + (8 * idsPerConstraint);
        int valuesVectorBytes = 4 + (idsPerConstraint * coefficientByteWidth);

        return SizePrefixBytes + tablesAndVtablesBytes + constraintsVectorBytes + idsVectorBytes + valuesVectorBytes;
    }


    /// <summary>
    /// Fills <paramref name="destination"/> — exactly <see cref="AliasedConstraintSystemStreamLength"/>
    /// bytes — with a single size-prefixed ConstraintSystem message whose <c>constraints</c> vector
    /// aliases <paramref name="constraintAliases"/> offset elements onto one shared BilinearConstraint
    /// with an <paramref name="idsPerConstraint"/>-element <c>lc_a</c> whose coefficients are
    /// <paramref name="coefficientByteWidth"/> bytes each (zero-filled, so an over-long width is a
    /// tolerated encoding). The reader assumes no field alignment, so the layout is packed and every
    /// offset points forward.
    /// </summary>
    private static void WriteAliasedConstraintSystemStream(Span<byte> destination, int constraintAliases, int idsPerConstraint, int coefficientByteWidth)
    {
        destination.Clear();

        int k = constraintAliases;
        int l = idsPerConstraint;
        int valueByteCount = idsPerConstraint * coefficientByteWidth;

        //The message body follows the 4-byte size prefix; positions below are relative to it.
        Span<byte> m = destination[SizePrefixBytes..];

        //Positions, low -> high address. Each vtable sits immediately before its table.
        const int pRootOffset = 0;                  //uoffset -> T_root (4 bytes).
        const int pVtRoot = 4;                       //8 bytes.
        const int pTRoot = 12;                       //9 bytes: soffset(4) msgType(1) msg-uoffset(4).
        const int pVtCs = 21;                        //6 bytes.
        const int pTCs = 27;                         //8 bytes: soffset(4) constraints-uoffset(4).
        const int pVConstraints = 35;                //4 + 4k.
        int pVtBc = pVConstraints + 4 + (4 * k);     //6 bytes.
        int pTBc = pVtBc + 6;                        //8 bytes: soffset(4) lcA-uoffset(4).
        int pVtVars = pTBc + 8;                      //8 bytes.
        int pTVars = pVtVars + 8;                    //12 bytes: soffset(4) ids-uoffset(4) values-uoffset(4).
        int pVIds = pTVars + 12;                     //4 + 8l.
        int pVValues = pVIds + 4 + (8 * l);          //4 + valueByteCount.
        int messageLength = pVValues + 4 + valueByteCount;

        //Root uoffset -> T_root.
        BinaryPrimitives.WriteUInt32LittleEndian(m[pRootOffset..], (uint)(pTRoot - pRootOffset));

        //VT_root: [vtableSize=8][tableSize=9][msgTypeOff=4][msgOff=5].
        BinaryPrimitives.WriteUInt16LittleEndian(m[pVtRoot..], 8);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtRoot + 2)..], 9);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtRoot + 4)..], 4);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtRoot + 6)..], 5);
        BinaryPrimitives.WriteInt32LittleEndian(m[pTRoot..], pTRoot - pVtRoot);
        m[pTRoot + 4] = (byte)ZkInterfaceMessageType.ConstraintSystem;
        BinaryPrimitives.WriteUInt32LittleEndian(m[(pTRoot + 5)..], (uint)(pTCs - (pTRoot + 5)));

        //VT_cs: [6][8][constraintsOff=4].
        BinaryPrimitives.WriteUInt16LittleEndian(m[pVtCs..], 6);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtCs + 2)..], 8);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtCs + 4)..], 4);
        BinaryPrimitives.WriteInt32LittleEndian(m[pTCs..], pTCs - pVtCs);
        BinaryPrimitives.WriteUInt32LittleEndian(m[(pTCs + 4)..], (uint)(pVConstraints - (pTCs + 4)));

        //V_constraints: length k, then k uoffsets all -> T_bc (the aliasing).
        BinaryPrimitives.WriteUInt32LittleEndian(m[pVConstraints..], (uint)k);
        for(int i = 0; i < k; i++)
        {
            int elemPos = pVConstraints + 4 + (4 * i);
            BinaryPrimitives.WriteUInt32LittleEndian(m[elemPos..], (uint)(pTBc - elemPos));
        }

        //VT_bc: [6][8][lcAOff=4] — lc_b, lc_c absent.
        BinaryPrimitives.WriteUInt16LittleEndian(m[pVtBc..], 6);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtBc + 2)..], 8);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtBc + 4)..], 4);
        BinaryPrimitives.WriteInt32LittleEndian(m[pTBc..], pTBc - pVtBc);
        BinaryPrimitives.WriteUInt32LittleEndian(m[(pTBc + 4)..], (uint)(pTVars - (pTBc + 4)));

        //VT_vars: [8][12][idsOff=4][valuesOff=8].
        BinaryPrimitives.WriteUInt16LittleEndian(m[pVtVars..], 8);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtVars + 2)..], 12);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtVars + 4)..], 4);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtVars + 6)..], 8);
        BinaryPrimitives.WriteInt32LittleEndian(m[pTVars..], pTVars - pVtVars);
        BinaryPrimitives.WriteUInt32LittleEndian(m[(pTVars + 4)..], (uint)(pVIds - (pTVars + 4)));
        BinaryPrimitives.WriteUInt32LittleEndian(m[(pTVars + 8)..], (uint)(pVValues - (pTVars + 8)));

        //V_ids: length l (uint64 element count), then l ids. V_values: length valueByteCount (a
        //ubyte vector, so its length prefix is a byte count), then that many zero bytes — element
        //size resolves to valueByteCount / l = coefficientByteWidth.
        BinaryPrimitives.WriteUInt32LittleEndian(m[pVIds..], (uint)l);
        for(int i = 0; i < l; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(m[(pVIds + 4 + (8 * i))..], (ulong)i);
        }

        BinaryPrimitives.WriteUInt32LittleEndian(m[pVValues..], (uint)valueByteCount);

        //The 4-byte little-endian size prefix carries the message length.
        BinaryPrimitives.WriteUInt32LittleEndian(destination, (uint)messageLength);
    }


    private static void AssertTerms(RecordingSink sink, int constraintIndex, ZkInterfaceConstraintMatrix matrix, ulong[] expectedIds)
    {
        var ids = new List<ulong>();
        foreach(RecordingSink.Term term in sink.Terms)
        {
            if(term.ConstraintIndex == constraintIndex && term.Matrix == matrix)
            {
                ids.Add(term.VariableId);
            }
        }

        CollectionAssert.AreEqual(expectedIds, ids, $"variable ids for constraint {constraintIndex} matrix {matrix}");
    }


    private sealed class RecordingSink: IZkInterfaceMessageSink
    {
        private int currentConstraint = -1;

        public ulong FreeVariableId { get; private set; }
        public bool FieldMaximumSeen { get; private set; }
        public int ConstraintCount { get; private set; }
        public List<ulong> InstanceVariableIds { get; } = new();
        public List<uint> InstanceVariableValues { get; } = new();
        public List<ulong> WitnessVariableIds { get; } = new();
        public List<uint> WitnessVariableValues { get; } = new();
        internal List<Term> Terms { get; } = [];


        public void OnFieldMaximum(ReadOnlySpan<byte> fieldMaximumLittleEndian) => FieldMaximumSeen = true;

        public void OnFreeVariableId(ulong freeVariableId) => FreeVariableId = freeVariableId;

        public void OnInstanceVariable(ulong variableId, ReadOnlySpan<byte> valueLittleEndian)
        {
            InstanceVariableIds.Add(variableId);
            InstanceVariableValues.Add(ReadLittleEndianValue(valueLittleEndian));
        }

        public void BeginConstraint()
        {
            currentConstraint++;
            ConstraintCount++;
        }

        public void OnConstraintTerm(ZkInterfaceConstraintMatrix matrix, ulong variableId, ReadOnlySpan<byte> coefficientLittleEndian) =>
            Terms.Add(new Term(currentConstraint, matrix, variableId, ReadLittleEndianValue(coefficientLittleEndian)));

        public void OnWitnessVariable(ulong variableId, ReadOnlySpan<byte> valueLittleEndian)
        {
            WitnessVariableIds.Add(variableId);
            WitnessVariableValues.Add(ReadLittleEndianValue(valueLittleEndian));
        }


        private static uint ReadLittleEndianValue(ReadOnlySpan<byte> littleEndian)
        {
            uint value = 0;
            for(int b = 0; b < littleEndian.Length && b < sizeof(uint); b++)
            {
                value |= (uint)littleEndian[b] << (8 * b);
            }

            return value;
        }


        internal readonly record struct Term(int ConstraintIndex, ZkInterfaceConstraintMatrix Matrix, ulong VariableId, uint Coefficient);
    }
}
