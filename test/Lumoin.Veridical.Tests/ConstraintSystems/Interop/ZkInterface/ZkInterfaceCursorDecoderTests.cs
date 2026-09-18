using Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.Metrics;
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
    /// <summary>The framing prefix is one little-endian unsigned 32-bit message length.</summary>
    private const int SizePrefixBytes = sizeof(uint);

    /// <summary>The table-to-vtable offset is a signed 32-bit FlatBuffers offset.</summary>
    private const int SignedOffsetBytes = sizeof(int);

    /// <summary>The root, table references and vector elements use unsigned 32-bit FlatBuffers offsets.</summary>
    private const int UnsignedOffsetBytes = sizeof(uint);

    /// <summary>Each FlatBuffers vector begins with an unsigned 32-bit element count.</summary>
    private const int VectorLengthBytes = sizeof(uint);

    /// <summary>The Root union discriminator occupies one byte in the schema.</summary>
    private const int UnionTypeBytes = sizeof(byte);

    /// <summary>The inline table size follows the vtable length, so it occupies the second vtable header entry.</summary>
    private const int TableSizeEntryOffset = VtableEntryBytes;

    /// <summary>The first field slot follows the two FlatBuffers vtable header entries.</summary>
    private const int FirstSlotEntryOffset = VtableHeaderEntries * VtableEntryBytes;

    /// <summary>The packed Root discriminator immediately follows its signed vtable offset.</summary>
    private const int RootTypeFieldOffset = SignedOffsetBytes;

    /// <summary>The packed Root union reference immediately follows its discriminator byte.</summary>
    private const int RootValueFieldOffset = RootTypeFieldOffset + UnionTypeBytes;

    /// <summary>The packed Root ends after its union reference, following its vtable offset and discriminator.</summary>
    private const int RootTableBytes = RootValueFieldOffset + UnsignedOffsetBytes;

    /// <summary>The Root vtable holds its two header entries and the discriminator and value slots.</summary>
    private const int RootVtableBytes = RootValueSlotEntryOffset + VtableEntryBytes;

    /// <summary>The sole field of each packed ConstraintSystem, Witness and BilinearConstraint follows its signed vtable offset.</summary>
    private const int SingleOffsetFieldOffset = SignedOffsetBytes;

    /// <summary>The packed ConstraintSystem, Witness and BilinearConstraint tables each hold a vtable offset and one reference.</summary>
    private const int SingleOffsetTableBytes = SingleOffsetFieldOffset + UnsignedOffsetBytes;

    /// <summary>The one-reference tables need two vtable header entries and one field slot.</summary>
    private const int SingleOffsetVtableBytes = FirstSlotEntryOffset + VtableEntryBytes;

    /// <summary>The packed Variables id-vector reference immediately follows its vtable offset.</summary>
    private const int VariablesIdsFieldOffset = SignedOffsetBytes;

    /// <summary>The packed Variables table ends after its second vector reference.</summary>
    private const int VariablesTableBytes = VariablesValuesFieldOffset + UnsignedOffsetBytes;

    /// <summary>The Variables vtable holds two header entries and the ids and values slots.</summary>
    private const int VariablesVtableBytes = RootValueSlotEntryOffset + VtableEntryBytes;

    /// <summary>The root reference begins the message body, so its body-relative position is zero.</summary>
    private const int RootOffsetPosition = 0;

    /// <summary>The packed Root vtable immediately follows the root reference.</summary>
    private const int RootVtablePosition = RootOffsetPosition + UnsignedOffsetBytes;

    /// <summary>The packed Root table immediately follows its vtable.</summary>
    private const int RootTablePosition = RootVtablePosition + RootVtableBytes;

    /// <summary>The ConstraintSystem or Witness vtable immediately follows the packed Root table.</summary>
    private const int PayloadVtablePosition = RootTablePosition + RootTableBytes;

    /// <summary>The ConstraintSystem or Witness table immediately follows its one-field vtable.</summary>
    private const int PayloadTablePosition = PayloadVtablePosition + SingleOffsetVtableBytes;

    /// <summary>The constraints vector or assigned Variables vtable immediately follows the payload table.</summary>
    private const int PayloadDataPosition = PayloadTablePosition + SingleOffsetTableBytes;

    /// <summary>The aliased stream framing comprises the root reference and the Root, ConstraintSystem, BilinearConstraint and Variables tables with their vtables.</summary>
    private const int AliasedTablesAndVtablesBytes = UnsignedOffsetBytes + RootVtableBytes + RootTableBytes + SingleOffsetVtableBytes + SingleOffsetTableBytes + SingleOffsetVtableBytes + SingleOffsetTableBytes + VariablesVtableBytes + VariablesTableBytes;

    /// <summary>The example header is the first message, so its stream-order index is zero.</summary>
    private const int HeaderMessageIndex = 0;

    /// <summary>The first example constraint squares variable one, so its zero-based index is zero.</summary>
    private const int FirstConstraintIndex = 0;

    /// <summary>The second example constraint squares variable two, so its zero-based index is one.</summary>
    private const int SecondConstraintIndex = 1;

    /// <summary>The example sum relation is the final constraint, following the two square relations.</summary>
    private const int LastConstraintIndex = ExampleConstraintCount - 1;

    /// <summary>Removing eight bytes cuts the final example message short while retaining its size prefix.</summary>
    private const int TruncatedByteCount = 8;

    /// <summary>Thirty-two aliased constraints amplify the term events beyond the packed stream byte budget.</summary>
    private const int EventConstraintAliases = 32;

    /// <summary>Thirty-two ids per shared combination make the aliased event count exceed the stream length.</summary>
    private const int EventIdsPerConstraint = 32;

    /// <summary>Eight aliases repeat the wide coefficient scan enough to exceed the byte budget with few events.</summary>
    private const int ScanConstraintAliases = 8;

    /// <summary>A 64-byte padded coefficient makes repeated scanning dominate the small event count.</summary>
    private const int WideCoefficientBytes = 64;

    /// <summary>With four zero-width terms per constraint, 117 aliases make both stream length and work equal 585.</summary>
    private const int ExactBudgetConstraintAliases = 117;

    /// <summary>Four zero-width terms per constraint balance the packed stream length at 117 aliases.</summary>
    private const int ExactBudgetIdsPerConstraint = 4;

    /// <summary>Sixteen aliases with 26 zero-width terms leave the combined constraint and witness work one unit over budget.</summary>
    private const int SharedBudgetConstraintAliases = 16;

    /// <summary>Twenty-six terms per shared combination make the combined constraint and witness work exceed their stream length by one.</summary>
    private const int SharedBudgetIdsPerConstraint = 26;

    /// <summary>A one-unit excess pins the shared budget boundary and requires every constraint and witness charge.</summary>
    private const int SharedBudgetOvershoot = 1;

    /// <summary>The sink starts before zero so the first begin callback assigns constraint index zero.</summary>
    private const int NoCurrentConstraint = -1;

    /// <summary>The fixture values are unsigned 32-bit integers, so the recording sink reads at most this many bytes.</summary>
    private const int FixtureValueBytes = sizeof(uint);

    /// <summary>Each successive byte contributes eight higher bits to the little-endian fixture value.</summary>
    private const int BitsPerByte = 8;

    /// <summary>The index of the first byte of a sequence: the running index of its first segment and the start offset within that segment.</summary>
    private const int SequenceStartIndex = 0;

    /// <summary>The byte at which the multi-segment decode splits example.zkif; any value strictly between zero and the 648-byte length leaves both segments non-empty.</summary>
    private const int SegmentSplitOffset = 256;

    /// <summary>The <c>free_variable_id</c> the example.zkif CircuitHeader declares (Fixtures/FIXTURES.md).</summary>
    private const ulong ExampleFreeVariableId = 6UL;

    /// <summary>The number of bilinear constraints in the example.zkif ConstraintSystem message.</summary>
    private const int ExampleConstraintCount = 3;

    /// <summary>The first variable id the example.zkif Witness message assigns.</summary>
    private const ulong ExampleFirstWitnessId = 4UL;

    /// <summary>The second variable id the example.zkif Witness message assigns.</summary>
    private const ulong ExampleSecondWitnessId = 5UL;

    /// <summary>The stream-order index of the ConstraintSystem message in example.zkif.</summary>
    private const int ConstraintSystemMessageIndex = 1;

    /// <summary>The width of one FlatBuffers vtable entry, a little-endian <see cref="ushort"/>.</summary>
    private const int VtableEntryBytes = sizeof(ushort);

    /// <summary>The number of header entries, the vtable byte length and the table inline size, that precede the field-slot entries of a vtable.</summary>
    private const int VtableHeaderEntries = 2;

    /// <summary>The vtable slot of the <c>Root.message</c> union value, which follows the discriminator slot.</summary>
    private const int RootMessageValueSlot = 1;

    /// <summary>The byte offset, from the start of the Root vtable, of the entry that locates the union value field.</summary>
    private const int RootValueSlotEntryOffset = (VtableHeaderEntries + RootMessageValueSlot) * VtableEntryBytes;

    /// <summary>The vtable field offset FlatBuffers uses to mark a field absent.</summary>
    private const ushort AbsentFieldOffset = 0;

    /// <summary>The field offset of <c>Variables.values</c> in the packed Variables tables the stream writers lay out: it follows the table's four-byte soffset and the four-byte <c>variable_ids</c> uoffset.</summary>
    private const ushort VariablesValuesFieldOffset = SignedOffsetBytes + UnsignedOffsetBytes;

    /// <summary>The constraint count a decode observes when the stream's only ConstraintSystem message is skipped.</summary>
    private const int SkippedConstraintCount = 0;

    /// <summary>A single constraint, the shape of the hand-encoded ConstraintSystem streams that exercise one linear combination.</summary>
    private const int SingleConstraint = 1;

    /// <summary>An empty <c>variable_ids</c> vector.</summary>
    private const int NoVariableIds = 0;

    /// <summary>A <c>variable_ids</c> vector with one element.</summary>
    private const int OneVariableId = 1;

    /// <summary>A <c>variable_ids</c> vector with two elements.</summary>
    private const int TwoVariableIds = 2;

    /// <summary>An empty values vector.</summary>
    private const int NoValueBytes = 0;

    /// <summary>A one-byte values vector, a one-byte coefficient for a single variable id.</summary>
    private const int OneValueByte = 1;

    /// <summary>A values vector length that <see cref="TwoVariableIds"/> does not divide.</summary>
    private const int IndivisibleValueByteCount = 3;

    /// <summary>The packed byte length of the Witness message <see cref="WriteEmptyAssignedVariablesWitnessStream"/> writes.</summary>
    private const int EmptyWitnessMessageBytes = PayloadDataPosition + VariablesVtableBytes + VariablesTableBytes + VectorLengthBytes + VectorLengthBytes;

    /// <summary>The byte length of the size-prefixed stream <see cref="WriteEmptyAssignedVariablesWitnessStream"/> writes.</summary>
    private const int EmptyWitnessStreamBytes = SizePrefixBytes + EmptyWitnessMessageBytes;

    /// <summary>The number of messages in example.zkif, which is also the index a message appended after them is numbered with.</summary>
    private const int ExampleMessageCount = 3;

    /// <summary>The stream-order index of the Witness message, the last message in example.zkif.</summary>
    private const int WitnessMessageIndex = 2;

    /// <summary>A number of stray bytes after the last message that is too few to hold a size prefix.</summary>
    private const int TrailingByteCount = 2;

    /// <summary>The message size a size prefix declares when the stream ends before that many bytes follow it.</summary>
    private const int OverrunDeclaredMessageBytes = 8;

    /// <summary>The number of bytes that actually follow the size prefix declaring <see cref="OverrunDeclaredMessageBytes"/>.</summary>
    private const int OverrunPresentMessageBytes = 4;

    /// <summary>The width of one <c>variable_ids</c> element, a little-endian <see cref="ulong"/>.</summary>
    private const int VariableIdBytes = sizeof(ulong);


    /// <summary>The witness variable ids example.zkif assigns, in stream order.</summary>
    private static ulong[] ExampleWitnessVariableIds { get; } = [ExampleFirstWitnessId, ExampleSecondWitnessId];


    /// <summary>The pooled rentals opened during a test, released together in cleanup.</summary>
    private List<IDisposable> Disposables { get; } = [];


    /// <summary>Disposes every rental the test opened, most recent first.</summary>
    [TestCleanup]
    public void DisposeRentals()
    {
        for(int i = Disposables.Count - 1; i >= 0; i--)
        {
            Disposables[i].Dispose();
        }

        Disposables.Clear();
    }


    /// <summary>Empty single- and multi-segment streams retain their rejection without renting staging memory.</summary>
    /// <param name="multipleSegments">Whether the empty sequence has two distinct segment objects.</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public void EmptySequencesRentNothing(bool multipleSegments)
    {
        using var meter = new Meter(nameof(EmptySequencesRentNothing));
        using var listener = new MeterListener();
        long rents = 0;
        listener.InstrumentPublished = (instrument, observer) =>
        {
            if(ReferenceEquals(instrument.Meter, meter))
            {
                observer.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            if(instrument.Name == BaseMemoryPoolMetrics.BaseMemoryPoolRentOperationsTotal)
            {
                rents += measurement;
            }
        });
        listener.Start();
        using BaseMemoryPool pool = new(meter);

        ReadOnlySequence<byte> sequence = ReadOnlySequence<byte>.Empty;
        if(multipleSegments)
        {
            var first = new StreamSegment(ReadOnlyMemory<byte>.Empty, SequenceStartIndex);
            StreamSegment last = first.Append(ReadOnlyMemory<byte>.Empty);
            sequence = new ReadOnlySequence<byte>(first, SequenceStartIndex, last, SequenceStartIndex);
            Assert.IsFalse(sequence.IsSingleSegment);
        }

        var sink = new RecordingSink();
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
            ZkInterfaceCursorDecoder.Decoder(sequence, sink, pool, CancellationToken.None));

        Assert.Contains("contains no messages", exception.Message);
        Assert.AreEqual(0L, rents);
    }


    /// <summary>Locates the example header, constraint system and witness in order, with their size-prefixed ranges tiling the stream.</summary>
    [TestMethod]
    public void LocateMessagesYieldsHeaderConstraintSystemWitnessInOrder()
    {
        byte[] file = ZkInterfaceExampleFixture.ExampleBytes();

        IReadOnlyList<ZkInterfaceMessageSpan> messages = ZkInterfaceCursorDecoder.LocateMessages(file);

        Assert.HasCount(3, messages, "message count");
        Assert.AreEqual(ZkInterfaceMessageType.CircuitHeader, messages[HeaderMessageIndex].Type, "message 0");
        Assert.AreEqual(ZkInterfaceMessageType.ConstraintSystem, messages[ConstraintSystemMessageIndex].Type, "message 1");
        Assert.AreEqual(ZkInterfaceMessageType.Witness, messages[WitnessMessageIndex].Type, "message 2");

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


    /// <summary>Rejects a stream whose final message extends beyond the supplied bytes.</summary>
    [TestMethod]
    public void LocateMessagesRejectsTruncatedStream()
    {
        byte[] full = ZkInterfaceExampleFixture.ExampleBytes();
        //Cut mid-stream so the final message's declared size overruns.
        ReadOnlyMemory<byte> truncated = full.AsMemory(..(full.Length - TruncatedByteCount));

        Assert.ThrowsExactly<ArgumentException>(() => ZkInterfaceCursorDecoder.LocateMessages(truncated.Span));
    }


    /// <summary>Rejects a stream ending in too few trailing bytes to hold another size prefix.</summary>
    [TestMethod]
    public void LocateMessagesRejectsTrailingBytes()
    {
        Memory<byte> extended = RentExampleWithZeroTail(TrailingByteCount);

        Assert.ThrowsExactly<ArgumentException>(() => ZkInterfaceCursorDecoder.LocateMessages(extended.Span));
    }


    /// <summary>Pushes the example header values, constraint terms and witness assignments with their fixture identities and coefficients.</summary>
    [TestMethod]
    public void DecoderPushesExampleHeaderConstraintsAndWitness()
    {
        var sink = new RecordingSink();
        ZkInterfaceCursorDecoder.Decoder(new ReadOnlySequence<byte>(ZkInterfaceExampleFixture.ExampleBytes()), sink, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.AreEqual(6UL, sink.FreeVariableId, "free_variable_id");
        Assert.IsFalse(sink.FieldMaximumSeen, "field_maximum is absent in the toy sample");
        Assert.AreSequenceEqual(new ulong[] { 1, 2, 3 }, sink.InstanceVariableIds, "instance variable ids");
        Assert.AreSequenceEqual(new uint[] { 3, 4, 25 }, sink.InstanceVariableValues, "instance variable values");

        //Every coefficient in the three constraints is the field element one.
        Assert.AreEqual(3, sink.ConstraintCount, "constraint count");
        foreach(RecordingSink.Term term in sink.Terms)
        {
            Assert.AreEqual(1U, term.Coefficient, $"coefficient (constraint {term.ConstraintIndex}, {term.Matrix})");
        }

        //The first constraint squares v1 to produce v4.
        AssertTerms(sink, FirstConstraintIndex, ZkInterfaceConstraintMatrix.A, [1]);
        AssertTerms(sink, FirstConstraintIndex, ZkInterfaceConstraintMatrix.B, [1]);
        AssertTerms(sink, FirstConstraintIndex, ZkInterfaceConstraintMatrix.C, [4]);
        //The last constraint sums v4 and v5 to produce v3, so B spans two variables.
        AssertTerms(sink, LastConstraintIndex, ZkInterfaceConstraintMatrix.A, [0]);
        AssertTerms(sink, LastConstraintIndex, ZkInterfaceConstraintMatrix.B, [4, 5]);
        AssertTerms(sink, LastConstraintIndex, ZkInterfaceConstraintMatrix.C, [3]);

        Assert.AreSequenceEqual(new ulong[] { 4, 5 }, sink.WitnessVariableIds, "witness variable ids");
        Assert.AreSequenceEqual(new uint[] { 9, 16 }, sink.WitnessVariableValues, "witness variable values");
    }


    /// <summary>Rejects aliased constraint offsets whose repeated term events and coefficient scans exceed the stream byte budget.</summary>
    [TestMethod]
    public void DecoderRejectsOffsetAliasingAmplification()
    {
        AssertAliasedConstraintSystemRejected(BaseMemoryPool.Shared, EventConstraintAliases, EventIdsPerConstraint, OneValueByte);
    }


    /// <summary>Rejects aliased zero-width terms whose event count alone exceeds the stream byte budget.</summary>
    [TestMethod]
    public void DecoderRejectsTermCountAmplificationWithoutCoefficientBytes()
    {
        AssertAliasedConstraintSystemRejected(BaseMemoryPool.Shared, EventConstraintAliases, EventIdsPerConstraint, NoValueBytes);
    }


    /// <summary>Rejects aliased wide coefficients whose repeated scans exceed the stream byte budget despite a small event count.</summary>
    [TestMethod]
    public void DecoderRejectsCoefficientScanAmplification()
    {
        AssertAliasedConstraintSystemRejected(BaseMemoryPool.Shared, ScanConstraintAliases, OneVariableId, WideCoefficientBytes);
    }


    /// <summary>
    /// A stream presented as more than one sequence segment is joined into one contiguous buffer
    /// and decoded exactly as a single segment is, so the sink receives the example's header,
    /// constraints and witness. The segments are views over the fixture array, so the test holds
    /// no working buffer of its own.
    /// </summary>
    [TestMethod]
    public void DecoderJoinsMultiSegmentStreamBeforeDecoding()
    {
        byte[] file = ZkInterfaceExampleFixture.ExampleBytes();
        var first = new StreamSegment(file.AsMemory(..SegmentSplitOffset), SequenceStartIndex);
        StreamSegment last = first.Append(file.AsMemory(SegmentSplitOffset..));
        var sequence = new ReadOnlySequence<byte>(first, SequenceStartIndex, last, last.Memory.Length);
        Assert.IsFalse(sequence.IsSingleSegment, "the stream must span more than one segment");

        var sink = new RecordingSink();
        ZkInterfaceCursorDecoder.Decoder(sequence, sink, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.AreEqual(ExampleFreeVariableId, sink.FreeVariableId, "free_variable_id");
        Assert.AreEqual(ExampleConstraintCount, sink.ConstraintCount, "constraint count");
        Assert.AreSequenceEqual(ExampleWitnessVariableIds, sink.WitnessVariableIds, "witness variable ids");
    }


    /// <summary>
    /// The decoder frames every message before it decodes any, and it decodes a single-segment
    /// stream in place over the caller's memory, so a sink callback can rewrite a later message
    /// between the two passes. When the ConstraintSystem message's union value field is marked
    /// absent by the time that message is dispatched, the message is skipped and decoding goes on
    /// to the Witness that follows it. The stream is the byte array the fixture loader reads fresh
    /// from disk, as the other example tests in this class use it, so rewriting it touches no other
    /// test.
    /// </summary>
    [TestMethod]
    public void DecoderSkipsMessageWhoseUnionValueVanishesBeforeDispatch()
    {
        byte[] file = ZkInterfaceExampleFixture.ExampleBytes();
        ZkInterfaceMessageSpan target = ZkInterfaceCursorDecoder.LocateMessages(file)[ConstraintSystemMessageIndex];
        Assert.AreEqual(ZkInterfaceMessageType.ConstraintSystem, target.Type, "the cleared message must be the constraint system");

        //The message buffer opens with a uoffset to its root table, and the root table opens with
        //an soffset back to its vtable, where the union value entry sits at a fixed offset.
        ReadOnlySpan<byte> body = file.AsSpan(target.BufferStart, target.BufferLength);
        int rootPosition = (int)BinaryPrimitives.ReadUInt32LittleEndian(body);
        int vtablePosition = rootPosition - BinaryPrimitives.ReadInt32LittleEndian(body[rootPosition..]);
        int entryPosition = target.BufferStart + vtablePosition + RootValueSlotEntryOffset;
        Assert.AreNotEqual(AbsentFieldOffset, BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(entryPosition)), "the union value field must be present before decoding");

        var sink = new ValueSlotClearingSink(file, entryPosition);
        ZkInterfaceCursorDecoder.Decoder(new ReadOnlySequence<byte>(file), sink, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.AreEqual(SkippedConstraintCount, sink.ConstraintCount, "the message whose union value vanished is skipped");
        Assert.AreSequenceEqual(ExampleWitnessVariableIds, sink.WitnessVariableIds, "decoding continues past the skipped message");
    }


    /// <summary>
    /// A stream with no bytes holds no messages, and the framing step rejects it rather than
    /// letting the decode finish with nothing pushed to the sink.
    /// </summary>
    [TestMethod]
    public void DecoderRejectsEmptyStream()
    {
        var sink = new RecordingSink();

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
            ZkInterfaceCursorDecoder.Decoder(ReadOnlySequence<byte>.Empty, sink, BaseMemoryPool.Shared, CancellationToken.None));

        Assert.Contains("contains no messages", exception.Message, "the empty-stream framing guard must be what rejects the stream");
    }


    /// <summary>
    /// A Witness whose <c>assigned_variables</c> table carries an empty <c>variable_ids</c> vector
    /// beside an empty values vector is a legal encoding of an empty assignment: it decodes without
    /// error and pushes no witness variables.
    /// </summary>
    [TestMethod]
    public void DecoderAcceptsWitnessWithEmptyVariableIds()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(EmptyWitnessStreamBytes);
        Disposables.Add(owner);
        ReadOnlyMemory<byte> stream = owner.Memory[..EmptyWitnessStreamBytes];
        WriteEmptyAssignedVariablesWitnessStream(owner.Memory.Span[..EmptyWitnessStreamBytes]);

        var sink = new RecordingSink();
        ZkInterfaceCursorDecoder.Decoder(new ReadOnlySequence<byte>(stream), sink, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.IsEmpty(sink.WitnessVariableIds, "an empty variable_ids vector assigns nothing");
    }


    /// <summary>
    /// A present linear combination whose <c>variable_ids</c> vector is empty contributes a zero
    /// row: the constraint is still opened, it carries no terms, and the empty values vector beside
    /// the empty ids is accepted.
    /// </summary>
    [TestMethod]
    public void DecoderTreatsEmptyLinearCombinationAsZeroRow()
    {
        int streamLength = AliasedConstraintSystemStreamLength(SingleConstraint, NoVariableIds, NoValueBytes);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(streamLength);
        Disposables.Add(owner);
        ReadOnlyMemory<byte> stream = owner.Memory[..streamLength];
        WriteAliasedConstraintSystemStream(owner.Memory.Span[..streamLength], SingleConstraint, NoVariableIds, NoValueBytes, valuesPresent: true);

        var sink = new RecordingSink();
        ZkInterfaceCursorDecoder.Decoder(new ReadOnlySequence<byte>(stream), sink, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.AreEqual(SingleConstraint, sink.ConstraintCount, "the constraint is still opened");
        Assert.IsEmpty(sink.Terms, "an empty variable_ids vector contributes no terms");
    }


    /// <summary>
    /// A linear combination that lists variable ids while its Variables vtable marks the values
    /// field absent has no coefficients to pair with them, so the decoder rejects it rather than
    /// pushing each id with an empty coefficient.
    /// </summary>
    [TestMethod]
    public void DecoderRejectsLinearCombinationWithoutCoefficientValues()
    {
        int streamLength = AliasedConstraintSystemStreamLength(SingleConstraint, OneVariableId, OneValueByte);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(streamLength);
        Disposables.Add(owner);
        ReadOnlyMemory<byte> stream = owner.Memory[..streamLength];
        WriteAliasedConstraintSystemStream(owner.Memory.Span[..streamLength], SingleConstraint, OneVariableId, OneValueByte, valuesPresent: false);

        var sink = new RecordingSink();
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
            ZkInterfaceCursorDecoder.Decoder(new ReadOnlySequence<byte>(stream), sink, BaseMemoryPool.Shared, CancellationToken.None));

        Assert.Contains("no coefficient values", exception.Message, "the missing-values guard must be what rejects the combination");
    }


    /// <summary>
    /// A values vector whose byte length is not a whole multiple of the variable id count has no
    /// consistent coefficient width, so the decoder rejects it with both lengths in the message
    /// before any term reaches the sink, rather than truncating the width and decoding the ids.
    /// </summary>
    [TestMethod]
    public void DecoderRejectsValuesNotDivisibleByVariableIdCount()
    {
        int streamLength = AliasedConstraintSystemStreamLength(SingleConstraint, TwoVariableIds, IndivisibleValueByteCount);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(streamLength);
        Disposables.Add(owner);
        ReadOnlyMemory<byte> stream = owner.Memory[..streamLength];
        WriteAliasedConstraintSystemStream(owner.Memory.Span[..streamLength], SingleConstraint, TwoVariableIds, IndivisibleValueByteCount, valuesPresent: true);

        var sink = new RecordingSink();
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
            ZkInterfaceCursorDecoder.Decoder(new ReadOnlySequence<byte>(stream), sink, BaseMemoryPool.Shared, CancellationToken.None));

        Assert.Contains($"values length {IndivisibleValueByteCount} is not divisible by the {TwoVariableIds} variable id(s)", exception.Message, "the element-size divisibility guard must be what rejects the stream");
        Assert.IsEmpty(sink.Terms, "no term is pushed before the coefficient width is validated");
    }


    /// <summary>
    /// Stray bytes after the last message that are too few to hold a size prefix are rejected with a
    /// message that counts the stray bytes and names the last whole message before them, so the report
    /// locates where the stream stopped framing.
    /// </summary>
    [TestMethod]
    public void LocateMessagesReportsTrailingByteCountAndLastMessageIndex()
    {
        Memory<byte> stream = RentExampleWithZeroTail(TrailingByteCount);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() => ZkInterfaceCursorDecoder.LocateMessages(stream.Span));

        Assert.Contains($"stream has {TrailingByteCount} trailing byte(s) after message {WitnessMessageIndex}; too few for a {SizePrefixBytes}-byte size prefix", exception.Message, "the trailing-bytes guard must count the stray bytes and name the last message");
    }


    /// <summary>
    /// Four bytes after the last message exactly fill a size prefix, so they are read as one rather than
    /// reported as trailing bytes. A prefix of zero declares an empty message, which is rejected under the
    /// index that follows the messages before it.
    /// </summary>
    [TestMethod]
    public void LocateMessagesRejectsZeroSizePrefixThatEndsTheStream()
    {
        Memory<byte> stream = RentExampleWithZeroTail(SizePrefixBytes);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() => ZkInterfaceCursorDecoder.LocateMessages(stream.Span));

        Assert.Contains($"message {ExampleMessageCount} declares a zero-byte size", exception.Message, "the zero-size guard must reject the prefix under the next message index");
    }


    /// <summary>
    /// A size prefix that declares more bytes than remain in the stream is rejected with a message that
    /// gives both the declared size and the number of bytes actually left after the prefix.
    /// </summary>
    [TestMethod]
    public void LocateMessagesReportsDeclaredSizeAndRemainingBytes()
    {
        int streamLength = SizePrefixBytes + OverrunPresentMessageBytes;
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(streamLength);
        Disposables.Add(owner);
        Memory<byte> stream = owner.Memory[..streamLength];
        stream.Span.Clear();
        BinaryPrimitives.WriteUInt32LittleEndian(stream.Span, OverrunDeclaredMessageBytes);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() => ZkInterfaceCursorDecoder.LocateMessages(stream.Span));

        Assert.Contains($"declares size {OverrunDeclaredMessageBytes} bytes but only {OverrunPresentMessageBytes} bytes remain in the stream", exception.Message, "the message-bounds guard must report the declared size and the remaining bytes");
    }


    /// <summary>
    /// A message whose union discriminator names a ConstraintSystem while its vtable marks the union value
    /// absent is inconsistent, and framing rejects it with the discriminator and the missing value in the
    /// message rather than classifying it. The stream is the byte array the fixture loader reads fresh from
    /// disk, so clearing its vtable entry touches no other test.
    /// </summary>
    [TestMethod]
    public void LocateMessagesRejectsUnionTypeWithoutValue()
    {
        byte[] file = ZkInterfaceExampleFixture.ExampleBytes();
        ZkInterfaceMessageSpan target = ZkInterfaceCursorDecoder.LocateMessages(file)[ConstraintSystemMessageIndex];
        Assert.AreEqual(ZkInterfaceMessageType.ConstraintSystem, target.Type, "the altered message must be the constraint system");

        //The message buffer opens with a uoffset to its root table, and the root table opens with an
        //soffset back to its vtable, where the union value entry sits at a fixed offset.
        ReadOnlySpan<byte> body = file.AsSpan(target.BufferStart, target.BufferLength);
        int rootPosition = (int)BinaryPrimitives.ReadUInt32LittleEndian(body);
        int vtablePosition = rootPosition - BinaryPrimitives.ReadInt32LittleEndian(body[rootPosition..]);
        file.AsSpan(target.BufferStart + vtablePosition + RootValueSlotEntryOffset, VtableEntryBytes).Clear();

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() => ZkInterfaceCursorDecoder.LocateMessages(file));

        Assert.Contains($"message {ConstraintSystemMessageIndex} has an empty or inconsistent Root.message union (type {(byte)ZkInterfaceMessageType.ConstraintSystem}, value present: False)", exception.Message, "the union consistency guard must be what rejects the message");
    }


    /// <summary>
    /// A null sink is rejected by the decoder's own argument check with an <see cref="ArgumentNullException"/>
    /// naming the sink, rather than failing with a dereference when the first decoded field is pushed.
    /// </summary>
    [TestMethod]
    public void DecoderRejectsNullSink()
    {
        var source = new ReadOnlySequence<byte>(ZkInterfaceExampleFixture.ExampleBytes());

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(() =>
            ZkInterfaceCursorDecoder.Decoder(source, null!, BaseMemoryPool.Shared, CancellationToken.None));

        Assert.AreEqual("sink", exception.ParamName, "the sink argument check must be what rejects the call");
    }


    /// <summary>
    /// Cancellation is honoured between messages: a token that is already cancelled stops the decode with
    /// an <see cref="OperationCanceledException"/> carrying that token before any callback reaches the sink.
    /// </summary>
    [TestMethod]
    public void DecoderHonoursCancellationBeforeTheFirstMessage()
    {
        var source = new ReadOnlySequence<byte>(ZkInterfaceExampleFixture.ExampleBytes());
        var sink = new RecordingSink();
        var cancelled = new CancellationToken(canceled: true);

        OperationCanceledException exception = Assert.ThrowsExactly<OperationCanceledException>(() => ZkInterfaceCursorDecoder.Decoder(source, sink, BaseMemoryPool.Shared, cancelled));

        Assert.AreEqual(cancelled, exception.CancellationToken, "The cancellation exception must carry the token supplied to the decoder.");
        Assert.IsEmpty(sink.Callbacks, "Cancellation before the first message must prevent every sink callback.");
    }


    /// <summary>
    /// Every constraint the decoder opens is closed again once its three linear combinations are pushed,
    /// so each begin is followed by exactly that constraint's fixture terms and then its matching end.
    /// </summary>
    [TestMethod]
    public void DecoderClosesEveryConstraintItOpens()
    {
        var sink = new RecordingSink();
        ZkInterfaceCursorDecoder.Decoder(new ReadOnlySequence<byte>(ZkInterfaceExampleFixture.ExampleBytes()), sink, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.AreEqual(ExampleConstraintCount, sink.ConstraintCount, "constraints opened");
        Assert.AreEqual(ExampleConstraintCount, sink.EndedConstraintCount, "every opened constraint is closed");

        (string Name, RecordingSink.Term? Term)[] expectedCallbacks =
        [
            (nameof(RecordingSink.BeginConstraint), null),
            (nameof(RecordingSink.OnConstraintTerm), new(FirstConstraintIndex, ZkInterfaceConstraintMatrix.A, 1, 1)),
            (nameof(RecordingSink.OnConstraintTerm), new(FirstConstraintIndex, ZkInterfaceConstraintMatrix.B, 1, 1)),
            (nameof(RecordingSink.OnConstraintTerm), new(FirstConstraintIndex, ZkInterfaceConstraintMatrix.C, 4, 1)),
            (nameof(RecordingSink.EndConstraint), null),
            (nameof(RecordingSink.BeginConstraint), null),
            (nameof(RecordingSink.OnConstraintTerm), new(SecondConstraintIndex, ZkInterfaceConstraintMatrix.A, 2, 1)),
            (nameof(RecordingSink.OnConstraintTerm), new(SecondConstraintIndex, ZkInterfaceConstraintMatrix.B, 2, 1)),
            (nameof(RecordingSink.OnConstraintTerm), new(SecondConstraintIndex, ZkInterfaceConstraintMatrix.C, 5, 1)),
            (nameof(RecordingSink.EndConstraint), null),
            (nameof(RecordingSink.BeginConstraint), null),
            (nameof(RecordingSink.OnConstraintTerm), new(LastConstraintIndex, ZkInterfaceConstraintMatrix.A, 0, 1)),
            (nameof(RecordingSink.OnConstraintTerm), new(LastConstraintIndex, ZkInterfaceConstraintMatrix.B, 4, 1)),
            (nameof(RecordingSink.OnConstraintTerm), new(LastConstraintIndex, ZkInterfaceConstraintMatrix.B, 5, 1)),
            (nameof(RecordingSink.OnConstraintTerm), new(LastConstraintIndex, ZkInterfaceConstraintMatrix.C, 3, 1)),
            (nameof(RecordingSink.EndConstraint), null)
        ];
        var constraintCallbacks = new List<(string Name, RecordingSink.Term? Term)>();
        foreach(var callback in sink.Callbacks)
        {
            if(callback.Name is nameof(RecordingSink.BeginConstraint) or nameof(RecordingSink.OnConstraintTerm) or nameof(RecordingSink.EndConstraint))
            {
                constraintCallbacks.Add(callback);
            }
        }

        Assert.AreSequenceEqual(expectedCallbacks, constraintCallbacks,
            "Each begin must enclose the fixture terms for v1*v1=v4, v2*v2=v5 or 1*(v4+v5)=v3, all with coefficient one, before its end.");
    }


    /// <summary>
    /// The decode-work budget admits work up to the stream's byte length inclusive: a stream whose decode
    /// spends exactly its length decodes in full, and only work beyond the length is rejected.
    /// </summary>
    [TestMethod]
    public void DecoderAcceptsStreamWhoseWorkEqualsItsByteLength()
    {
        //Each aliased constraint charges one event and each of its zero-width terms one more, so the work is
        //117 x (1 + 4) = 585 units, and the packed stream is 85 + (4 x 117) + (8 x 4) = 585 bytes.

        int streamLength = AliasedConstraintSystemStreamLength(ExactBudgetConstraintAliases, ExactBudgetIdsPerConstraint, NoValueBytes);
        Assert.AreEqual(ExactBudgetConstraintAliases + (ExactBudgetConstraintAliases * ExactBudgetIdsPerConstraint), streamLength, "the decode work must equal the stream length");

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(streamLength);
        Disposables.Add(owner);
        ReadOnlyMemory<byte> stream = owner.Memory[..streamLength];
        WriteAliasedConstraintSystemStream(owner.Memory.Span[..streamLength], ExactBudgetConstraintAliases, ExactBudgetIdsPerConstraint, NoValueBytes, valuesPresent: true);

        var sink = new RecordingSink();
        ZkInterfaceCursorDecoder.Decoder(new ReadOnlySequence<byte>(stream), sink, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.AreEqual(ExactBudgetConstraintAliases, sink.ConstraintCount, "every aliased constraint is decoded");
        Assert.HasCount(ExactBudgetConstraintAliases * ExactBudgetIdsPerConstraint, sink.Terms, "every term is decoded");
    }


    /// <summary>
    /// One decode-work budget spans every message in the stream, and it charges a constraint's own event
    /// as well as a witness assignment's event and value bytes. A ConstraintSystem followed by a Witness
    /// whose combined work exceeds the stream length by one unit is rejected, and each of those charges is
    /// needed for the work to exceed the length.
    /// </summary>
    [TestMethod]
    public void DecoderChargesConstraintsAndAssignmentsAgainstOneStreamBudget()
    {
        //The ConstraintSystem spends 16 x (1 + 26) = 432 units in 85 + (4 x 16) + (8 x 26) = 357 bytes. The
        //Witness assigns one id with a one-byte value, one event and one scanned byte, in 67 + 8 + 1 = 76
        //bytes. The stream is 433 bytes and the work 434 units.

        int constraintSystemLength = AliasedConstraintSystemStreamLength(SharedBudgetConstraintAliases, SharedBudgetIdsPerConstraint, NoValueBytes);
        int witnessLength = AssignedVariablesWitnessStreamLength(OneVariableId, OneValueByte);
        int streamLength = constraintSystemLength + witnessLength;
        int work = SharedBudgetConstraintAliases + (SharedBudgetConstraintAliases * SharedBudgetIdsPerConstraint) + OneVariableId + OneValueByte;
        Assert.AreEqual(streamLength + SharedBudgetOvershoot, work, "the decode work must exceed the stream length by exactly one unit");

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(streamLength);
        Disposables.Add(owner);
        ReadOnlyMemory<byte> stream = owner.Memory[..streamLength];
        WriteAliasedConstraintSystemStream(owner.Memory.Span[..constraintSystemLength], SharedBudgetConstraintAliases, SharedBudgetIdsPerConstraint, NoValueBytes, valuesPresent: true);
        WriteAssignedVariablesWitnessStream(owner.Memory.Span[constraintSystemLength..streamLength], OneVariableId, OneValueByte);

        var sink = new RecordingSink();
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
            ZkInterfaceCursorDecoder.Decoder(new ReadOnlySequence<byte>(stream), sink, BaseMemoryPool.Shared, CancellationToken.None));

        Assert.Contains("more work than its byte length", exception.Message, "the decode-work budget must be what rejects the stream");
    }


    /// <summary>
    /// Rents a pooled buffer holding example.zkif followed by <paramref name="tailBytes"/> zero bytes and
    /// registers the rental for cleanup.
    /// </summary>
    /// <param name="tailBytes">The number of zero bytes appended after the example stream.</param>
    /// <returns>The example stream and its zero tail, exactly as long as both together.</returns>
    private Memory<byte> RentExampleWithZeroTail(int tailBytes)
    {
        byte[] example = ZkInterfaceExampleFixture.ExampleBytes();
        int streamLength = example.Length + tailBytes;
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(streamLength);
        Disposables.Add(owner);
        Memory<byte> stream = owner.Memory[..streamLength];
        example.AsSpan().CopyTo(stream.Span);
        stream.Span[example.Length..].Clear();

        return stream;
    }


    /// <summary>Encodes the given aliased constraint shape and requires the decode-work budget rejection message, so a bounds failure cannot satisfy the assertion.</summary>
    /// <param name="pool">The pool supplied by the test.</param>
    /// <param name="constraintAliases">The aliased constraint count.</param>
    /// <param name="idsPerConstraint">The variable identifiers per constraint.</param>
    /// <param name="coefficientByteWidth">The coefficient width in bytes.</param>
    private static void AssertAliasedConstraintSystemRejected(BaseMemoryPool pool, int constraintAliases, int idsPerConstraint, int coefficientByteWidth)
    {
        int valueByteCount = idsPerConstraint * coefficientByteWidth;
        int streamLength = AliasedConstraintSystemStreamLength(constraintAliases, idsPerConstraint, valueByteCount);
        using IMemoryOwner<byte> owner = pool.Rent(streamLength);
        ReadOnlyMemory<byte> stream = owner.Memory[..streamLength];
        WriteAliasedConstraintSystemStream(owner.Memory.Span[..streamLength], constraintAliases, idsPerConstraint, valueByteCount, valuesPresent: true);

        var sink = new RecordingSink();
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
            ZkInterfaceCursorDecoder.Decoder(new ReadOnlySequence<byte>(stream), sink, pool, CancellationToken.None));

        Assert.Contains("more work than its byte length", exception.Message, "the decode-work budget must be what rejects the aliased stream");
    }


    /// <summary>Computes the packed aliased stream length from its framing and the constraint-offset, variable-id and coefficient-value vectors.</summary>
    private static int AliasedConstraintSystemStreamLength(int constraintAliases, int idsPerConstraint, int valueByteCount)
    {
        int constraintsVectorBytes = VectorLengthBytes + (UnsignedOffsetBytes * constraintAliases);
        int idsVectorBytes = VectorLengthBytes + (VariableIdBytes * idsPerConstraint);
        int valuesVectorBytes = VectorLengthBytes + valueByteCount;

        return SizePrefixBytes + AliasedTablesAndVtablesBytes + constraintsVectorBytes + idsVectorBytes + valuesVectorBytes;
    }


    /// <summary>
    /// Fills <paramref name="destination"/> — exactly <see cref="AliasedConstraintSystemStreamLength"/>
    /// bytes — with a single size-prefixed ConstraintSystem message whose <c>constraints</c> vector
    /// aliases <paramref name="constraintAliases"/> offset elements onto one shared BilinearConstraint
    /// with an <paramref name="idsPerConstraint"/>-element <c>lc_a</c> whose zero-filled values vector
    /// holds <paramref name="valueByteCount"/> bytes. The decoder takes the coefficient width to be
    /// <paramref name="valueByteCount"/> divided by <paramref name="idsPerConstraint"/>, so an
    /// over-long width is a tolerated encoding and a count the ids do not divide is not. When
    /// <paramref name="valuesPresent"/> is <see langword="false"/>, the Variables vtable marks the
    /// values field absent while the values vector bytes stay in place. The reader assumes no field
    /// alignment, so the layout is packed and every offset points forward.
    /// </summary>
    private static void WriteAliasedConstraintSystemStream(Span<byte> destination, int constraintAliases, int idsPerConstraint, int valueByteCount, bool valuesPresent)
    {
        destination.Clear();

        Span<byte> message = destination[SizePrefixBytes..];

        //Each vtable immediately precedes its table; vector payloads determine the later positions.
        int constraintsPosition = PayloadDataPosition;
        int constraintVtablePosition = constraintsPosition + VectorLengthBytes + (UnsignedOffsetBytes * constraintAliases);
        int constraintTablePosition = constraintVtablePosition + SingleOffsetVtableBytes;
        int variablesVtablePosition = constraintTablePosition + SingleOffsetTableBytes;
        int variablesTablePosition = variablesVtablePosition + VariablesVtableBytes;
        int idsPosition = variablesTablePosition + VariablesTableBytes;
        int valuesPosition = idsPosition + VectorLengthBytes + (VariableIdBytes * idsPerConstraint);
        int messageLength = valuesPosition + VectorLengthBytes + valueByteCount;

        BinaryPrimitives.WriteUInt32LittleEndian(message[RootOffsetPosition..], RootTablePosition - RootOffsetPosition);

        //The Root identifies the ConstraintSystem and points to its table.
        BinaryPrimitives.WriteUInt16LittleEndian(message[RootVtablePosition..], RootVtableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(message[(RootVtablePosition + TableSizeEntryOffset)..], RootTableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(message[(RootVtablePosition + FirstSlotEntryOffset)..], RootTypeFieldOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(message[(RootVtablePosition + RootValueSlotEntryOffset)..], RootValueFieldOffset);
        BinaryPrimitives.WriteInt32LittleEndian(message[RootTablePosition..], RootTablePosition - RootVtablePosition);
        message[RootTablePosition + RootTypeFieldOffset] = (byte)ZkInterfaceMessageType.ConstraintSystem;
        BinaryPrimitives.WriteUInt32LittleEndian(message[(RootTablePosition + RootValueFieldOffset)..], PayloadTablePosition - (RootTablePosition + RootValueFieldOffset));

        //The ConstraintSystem points to the aliased constraints vector.
        BinaryPrimitives.WriteUInt16LittleEndian(message[PayloadVtablePosition..], SingleOffsetVtableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(message[(PayloadVtablePosition + TableSizeEntryOffset)..], SingleOffsetTableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(message[(PayloadVtablePosition + FirstSlotEntryOffset)..], SingleOffsetFieldOffset);
        BinaryPrimitives.WriteInt32LittleEndian(message[PayloadTablePosition..], PayloadTablePosition - PayloadVtablePosition);
        BinaryPrimitives.WriteUInt32LittleEndian(message[(PayloadTablePosition + SingleOffsetFieldOffset)..], (uint)(constraintsPosition - (PayloadTablePosition + SingleOffsetFieldOffset)));

        //Every vector element points to the same BilinearConstraint table.
        BinaryPrimitives.WriteUInt32LittleEndian(message[constraintsPosition..], (uint)constraintAliases);
        for(int i = 0; i < constraintAliases; i++)
        {
            int elementPosition = constraintsPosition + VectorLengthBytes + (UnsignedOffsetBytes * i);
            BinaryPrimitives.WriteUInt32LittleEndian(message[elementPosition..], (uint)(constraintTablePosition - elementPosition));
        }

        //Only lc_a is present, so lc_b and lc_c contribute no terms.
        BinaryPrimitives.WriteUInt16LittleEndian(message[constraintVtablePosition..], SingleOffsetVtableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(message[(constraintVtablePosition + TableSizeEntryOffset)..], SingleOffsetTableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(message[(constraintVtablePosition + FirstSlotEntryOffset)..], SingleOffsetFieldOffset);
        BinaryPrimitives.WriteInt32LittleEndian(message[constraintTablePosition..], constraintTablePosition - constraintVtablePosition);
        BinaryPrimitives.WriteUInt32LittleEndian(message[(constraintTablePosition + SingleOffsetFieldOffset)..], (uint)(variablesTablePosition - (constraintTablePosition + SingleOffsetFieldOffset)));

        //The Variables table retains both vectors even when its values slot marks the field absent.
        BinaryPrimitives.WriteUInt16LittleEndian(message[variablesVtablePosition..], VariablesVtableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(message[(variablesVtablePosition + TableSizeEntryOffset)..], VariablesTableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(message[(variablesVtablePosition + FirstSlotEntryOffset)..], VariablesIdsFieldOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(message[(variablesVtablePosition + RootValueSlotEntryOffset)..], valuesPresent ? VariablesValuesFieldOffset : AbsentFieldOffset);
        BinaryPrimitives.WriteInt32LittleEndian(message[variablesTablePosition..], variablesTablePosition - variablesVtablePosition);
        BinaryPrimitives.WriteUInt32LittleEndian(message[(variablesTablePosition + VariablesIdsFieldOffset)..], (uint)(idsPosition - (variablesTablePosition + VariablesIdsFieldOffset)));
        BinaryPrimitives.WriteUInt32LittleEndian(message[(variablesTablePosition + VariablesValuesFieldOffset)..], (uint)(valuesPosition - (variablesTablePosition + VariablesValuesFieldOffset)));

        //The ids vector counts ulong elements; the values vector counts zero-filled coefficient bytes.
        BinaryPrimitives.WriteUInt32LittleEndian(message[idsPosition..], (uint)idsPerConstraint);
        for(int i = 0; i < idsPerConstraint; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(message[(idsPosition + VectorLengthBytes + (VariableIdBytes * i))..], (ulong)i);
        }

        BinaryPrimitives.WriteUInt32LittleEndian(message[valuesPosition..], (uint)valueByteCount);
        BinaryPrimitives.WriteUInt32LittleEndian(destination, (uint)messageLength);
    }


    /// <summary>
    /// Fills <paramref name="destination"/>, exactly <see cref="EmptyWitnessStreamBytes"/> bytes, with
    /// a single size-prefixed Witness message whose <c>assigned_variables</c> table holds an empty
    /// <c>variable_ids</c> vector and an empty values vector. Every table size, vtable size and field
    /// offset is derived from the widths of the FlatBuffers building blocks; the layout is packed and
    /// every offset points forward.
    /// </summary>
    private static void WriteEmptyAssignedVariablesWitnessStream(Span<byte> destination) =>
        WriteAssignedVariablesWitnessStream(destination, NoVariableIds, NoValueBytes);


    /// <summary>
    /// The byte length of the size-prefixed stream <see cref="WriteAssignedVariablesWitnessStream"/> writes:
    /// the empty Witness stream grown by one <c>variable_ids</c> element per id and by the value bytes.
    /// </summary>
    /// <param name="idCount">The number of variable ids the Witness assigns.</param>
    /// <param name="valueByteCount">The byte length of the values vector.</param>
    /// <returns>The stream length in bytes, size prefix included.</returns>
    private static int AssignedVariablesWitnessStreamLength(int idCount, int valueByteCount) =>
        EmptyWitnessStreamBytes + (VariableIdBytes * idCount) + valueByteCount;


    /// <summary>
    /// Fills <paramref name="destination"/>, exactly <see cref="AssignedVariablesWitnessStreamLength"/>
    /// bytes, with a single size-prefixed Witness message whose <c>assigned_variables</c> table holds
    /// <paramref name="idCount"/> variable ids, numbered from zero, and a zero-filled values vector of
    /// <paramref name="valueByteCount"/> bytes. Every table size, vtable size and field offset is derived
    /// from the widths of the FlatBuffers building blocks; the layout is packed and every offset points
    /// forward.
    /// </summary>
    /// <param name="destination">The span the stream is written into.</param>
    /// <param name="idCount">The number of variable ids the Witness assigns.</param>
    /// <param name="valueByteCount">The byte length of the values vector.</param>
    private static void WriteAssignedVariablesWitnessStream(Span<byte> destination, int idCount, int valueByteCount)
    {
        destination.Clear();

        //The assigned Variables vtable follows the Witness; both vectors follow the Variables table.
        int variablesVtablePosition = PayloadDataPosition;
        int variablesTablePosition = variablesVtablePosition + VariablesVtableBytes;
        int idsPosition = variablesTablePosition + VariablesTableBytes;
        int valuesPosition = idsPosition + VectorLengthBytes + (VariableIdBytes * idCount);
        int messageLength = valuesPosition + VectorLengthBytes + valueByteCount;
        Span<byte> message = destination[SizePrefixBytes..];

        BinaryPrimitives.WriteUInt32LittleEndian(message[RootOffsetPosition..], RootTablePosition - RootOffsetPosition);

        //The Root identifies the Witness and points to its table.
        BinaryPrimitives.WriteUInt16LittleEndian(message[RootVtablePosition..], RootVtableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(message[(RootVtablePosition + TableSizeEntryOffset)..], RootTableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(message[(RootVtablePosition + FirstSlotEntryOffset)..], RootTypeFieldOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(message[(RootVtablePosition + RootValueSlotEntryOffset)..], RootValueFieldOffset);
        BinaryPrimitives.WriteInt32LittleEndian(message[RootTablePosition..], RootTablePosition - RootVtablePosition);
        message[RootTablePosition + RootTypeFieldOffset] = (byte)ZkInterfaceMessageType.Witness;
        BinaryPrimitives.WriteUInt32LittleEndian(message[(RootTablePosition + RootValueFieldOffset)..], PayloadTablePosition - (RootTablePosition + RootValueFieldOffset));

        //The Witness points to the table holding its assigned variables.
        BinaryPrimitives.WriteUInt16LittleEndian(message[PayloadVtablePosition..], SingleOffsetVtableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(message[(PayloadVtablePosition + TableSizeEntryOffset)..], SingleOffsetTableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(message[(PayloadVtablePosition + FirstSlotEntryOffset)..], SingleOffsetFieldOffset);
        BinaryPrimitives.WriteInt32LittleEndian(message[PayloadTablePosition..], PayloadTablePosition - PayloadVtablePosition);
        BinaryPrimitives.WriteUInt32LittleEndian(message[(PayloadTablePosition + SingleOffsetFieldOffset)..], (uint)(variablesTablePosition - (PayloadTablePosition + SingleOffsetFieldOffset)));

        //The Variables table points to its id and value vectors.
        BinaryPrimitives.WriteUInt16LittleEndian(message[variablesVtablePosition..], VariablesVtableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(message[(variablesVtablePosition + TableSizeEntryOffset)..], VariablesTableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(message[(variablesVtablePosition + FirstSlotEntryOffset)..], VariablesIdsFieldOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(message[(variablesVtablePosition + RootValueSlotEntryOffset)..], VariablesValuesFieldOffset);
        BinaryPrimitives.WriteInt32LittleEndian(message[variablesTablePosition..], variablesTablePosition - variablesVtablePosition);
        BinaryPrimitives.WriteUInt32LittleEndian(message[(variablesTablePosition + VariablesIdsFieldOffset)..], (uint)(idsPosition - (variablesTablePosition + VariablesIdsFieldOffset)));
        BinaryPrimitives.WriteUInt32LittleEndian(message[(variablesTablePosition + VariablesValuesFieldOffset)..], (uint)(valuesPosition - (variablesTablePosition + VariablesValuesFieldOffset)));

        //The ids vector counts elements; the values vector counts bytes that remain zero after clearing.
        BinaryPrimitives.WriteUInt32LittleEndian(message[idsPosition..], (uint)idCount);
        for(int i = 0; i < idCount; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(message[(idsPosition + VectorLengthBytes + (VariableIdBytes * i))..], (ulong)i);
        }

        BinaryPrimitives.WriteUInt32LittleEndian(message[valuesPosition..], (uint)valueByteCount);
        BinaryPrimitives.WriteUInt32LittleEndian(destination, (uint)messageLength);
    }


    /// <summary>Checks the fixture variable ids in stream order for one matrix of one constraint.</summary>
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

        Assert.AreSequenceEqual(expectedIds, ids, $"variable ids for constraint {constraintIndex} matrix {matrix}");
    }


    /// <summary>Records every decoder callback in arrival order together with the example's header, terms and witness values.</summary>
    private sealed class RecordingSink: IZkInterfaceMessageSink
    {
        /// <summary>The zero-based index assigned by the latest begin callback, initially before the first constraint.</summary>
        private int currentConstraint = NoCurrentConstraint;

        /// <summary>The free variable id supplied by the header.</summary>
        public ulong FreeVariableId { get; private set; }

        /// <summary>Whether the header supplies a field maximum.</summary>
        public bool FieldMaximumSeen { get; private set; }

        /// <summary>The number of constraints the decoder opened.</summary>
        public int ConstraintCount { get; private set; }

        /// <summary>The number of constraints the decoder closed.</summary>
        public int EndedConstraintCount { get; private set; }

        /// <summary>The public variable ids supplied by the header, in callback order.</summary>
        public List<ulong> InstanceVariableIds { get; } = new();

        /// <summary>The public values supplied by the header, in callback order.</summary>
        public List<uint> InstanceVariableValues { get; } = new();

        /// <summary>The variable ids assigned by the witness, in callback order.</summary>
        public List<ulong> WitnessVariableIds { get; } = new();

        /// <summary>The values assigned by the witness, in callback order.</summary>
        public List<uint> WitnessVariableValues { get; } = new();

        /// <summary>The constraint terms paired with the latest begin callback's index.</summary>
        internal List<Term> Terms { get; } = [];

        /// <summary>Every sink callback's name in arrival order, with its term payload when it delivers a constraint term.</summary>
        internal List<(string Name, Term? Term)> Callbacks { get; } = [];


        /// <summary>Records the field-maximum callback and marks the field present.</summary>
        public void OnFieldMaximum(ReadOnlySpan<byte> fieldMaximumLittleEndian)
        {
            Callbacks.Add((nameof(OnFieldMaximum), null));
            FieldMaximumSeen = true;
        }


        /// <summary>Records the header's free variable id and the callback's position in the stream.</summary>
        public void OnFreeVariableId(ulong freeVariableId)
        {
            Callbacks.Add((nameof(OnFreeVariableId), null));
            FreeVariableId = freeVariableId;
        }


        /// <summary>Records one public variable's id and value and the callback's position in the stream.</summary>
        public void OnInstanceVariable(ulong variableId, ReadOnlySpan<byte> valueLittleEndian)
        {
            Callbacks.Add((nameof(OnInstanceVariable), null));
            InstanceVariableIds.Add(variableId);
            InstanceVariableValues.Add(ReadLittleEndianValue(valueLittleEndian));
        }


        /// <summary>Records a begin callback and advances the constraint index and count.</summary>
        public void BeginConstraint()
        {
            Callbacks.Add((nameof(BeginConstraint), null));
            currentConstraint++;
            ConstraintCount++;
        }


        /// <summary>Records one term with its matrix, variable, coefficient and current constraint index at its callback position.</summary>
        public void OnConstraintTerm(ZkInterfaceConstraintMatrix matrix, ulong variableId, ReadOnlySpan<byte> coefficientLittleEndian)
        {
            var term = new Term(currentConstraint, matrix, variableId, ReadLittleEndianValue(coefficientLittleEndian));
            Callbacks.Add((nameof(OnConstraintTerm), term));
            Terms.Add(term);
        }


        /// <summary>Records an end callback and counts one closed constraint.</summary>
        public void EndConstraint()
        {
            Callbacks.Add((nameof(EndConstraint), null));
            EndedConstraintCount++;
        }


        /// <summary>Records one witness variable's id and value and the callback's position in the stream.</summary>
        public void OnWitnessVariable(ulong variableId, ReadOnlySpan<byte> valueLittleEndian)
        {
            Callbacks.Add((nameof(OnWitnessVariable), null));
            WitnessVariableIds.Add(variableId);
            WitnessVariableValues.Add(ReadLittleEndianValue(valueLittleEndian));
        }


        /// <summary>Reads the fixture's low unsigned 32-bit value, treating an empty coefficient as zero.</summary>
        private static uint ReadLittleEndianValue(ReadOnlySpan<byte> littleEndian)
        {
            uint value = 0;
            for(int b = 0; b < littleEndian.Length && b < FixtureValueBytes; b++)
            {
                value |= (uint)littleEndian[b] << (BitsPerByte * b);
            }

            return value;
        }


        /// <summary>A recorded fixture term identified by its constraint, matrix, variable id and unsigned coefficient.</summary>
        /// <param name="ConstraintIndex">The zero-based constraint index assigned by begin callbacks.</param>
        /// <param name="Matrix">The linear combination receiving the term.</param>
        /// <param name="VariableId">The variable multiplied by the coefficient.</param>
        /// <param name="Coefficient">The coefficient's low unsigned 32-bit value.</param>
        internal readonly record struct Term(int ConstraintIndex, ZkInterfaceConstraintMatrix Matrix, ulong VariableId, uint Coefficient);
    }


    /// <summary>
    /// One segment of a hand-linked <see cref="ReadOnlySequence{T}"/>, used to present a stream to
    /// the decoder in more than one piece.
    /// </summary>
    private sealed class StreamSegment: ReadOnlySequenceSegment<byte>
    {
        /// <summary>Creates a segment over <paramref name="memory"/> that begins at <paramref name="runningIndex"/> within the whole sequence.</summary>
        /// <param name="memory">The bytes this segment holds.</param>
        /// <param name="runningIndex">The sequence index of this segment's first byte.</param>
        public StreamSegment(ReadOnlyMemory<byte> memory, long runningIndex)
        {
            Memory = memory;
            RunningIndex = runningIndex;
        }


        /// <summary>Links a new segment over <paramref name="memory"/> directly after this one and returns it.</summary>
        /// <param name="memory">The bytes the new segment holds.</param>
        /// <returns>The appended segment.</returns>
        public StreamSegment Append(ReadOnlyMemory<byte> memory)
        {
            var next = new StreamSegment(memory, RunningIndex + Memory.Length);
            Next = next;

            return next;
        }
    }


    /// <summary>
    /// A sink that clears one two-byte vtable entry of the stream it is decoding when the
    /// CircuitHeader's <c>free_variable_id</c> arrives, and records the constraints and witness
    /// variables pushed to it. The other callbacks keep the interface's no-op defaults.
    /// </summary>
    /// <param name="source">The stream being decoded, rewritten in place.</param>
    /// <param name="entryPosition">The absolute stream position of the vtable entry to clear.</param>
    private sealed class ValueSlotClearingSink(byte[] source, int entryPosition): IZkInterfaceMessageSink
    {
        /// <summary>The number of constraints the decoder opened.</summary>
        public int ConstraintCount { get; private set; }

        /// <summary>The witness variable ids pushed, in stream order.</summary>
        public List<ulong> WitnessVariableIds { get; } = [];

        /// <summary>The stream being decoded, rewritten in place.</summary>
        private byte[] Source { get; } = source;

        /// <summary>The absolute stream position of the vtable entry to clear.</summary>
        private int EntryPosition { get; } = entryPosition;


        /// <summary>Clears the vtable entry, so every later read of that table sees the field absent.</summary>
        /// <param name="freeVariableId">The header's free variable id, not used.</param>
        public void OnFreeVariableId(ulong freeVariableId) => Source.AsSpan(EntryPosition, VtableEntryBytes).Clear();


        /// <summary>Counts one opened constraint.</summary>
        public void BeginConstraint() => ConstraintCount++;


        /// <summary>Records the id of one witness variable.</summary>
        /// <param name="variableId">The assigned variable id.</param>
        /// <param name="valueLittleEndian">The assigned value, not used.</param>
        public void OnWitnessVariable(ulong variableId, ReadOnlySpan<byte> valueLittleEndian) => WitnessVariableIds.Add(variableId);
    }
}
