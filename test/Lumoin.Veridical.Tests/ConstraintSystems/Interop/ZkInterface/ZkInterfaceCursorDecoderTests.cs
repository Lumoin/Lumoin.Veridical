using Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;
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
