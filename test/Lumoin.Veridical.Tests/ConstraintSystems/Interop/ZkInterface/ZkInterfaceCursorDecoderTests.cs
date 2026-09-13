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
    private const ushort VariablesValuesFieldOffset = sizeof(int) + sizeof(uint);

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
    private const int EmptyWitnessMessageBytes = 63;

    /// <summary>The byte length of the size-prefixed stream <see cref="WriteEmptyAssignedVariablesWitnessStream"/> writes.</summary>
    private const int EmptyWitnessStreamBytes = SizePrefixBytes + EmptyWitnessMessageBytes;


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
        Assert.AreSequenceEqual(new ulong[] { 1, 2, 3 }, sink.InstanceVariableIds, "instance variable ids");
        Assert.AreSequenceEqual(new uint[] { 3, 4, 25 }, sink.InstanceVariableValues, "instance variable values");

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
        Assert.AreSequenceEqual(new ulong[] { 4, 5 }, sink.WitnessVariableIds, "witness variable ids");
        Assert.AreSequenceEqual(new uint[] { 9, 16 }, sink.WitnessVariableValues, "witness variable values");
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
        ZkInterfaceCursorDecoder.Decoder(sequence, sink, CancellationToken.None);

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
        ZkInterfaceCursorDecoder.Decoder(new ReadOnlySequence<byte>(file), sink, CancellationToken.None);

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
            ZkInterfaceCursorDecoder.Decoder(ReadOnlySequence<byte>.Empty, sink, CancellationToken.None));

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
        ZkInterfaceCursorDecoder.Decoder(new ReadOnlySequence<byte>(stream), sink, CancellationToken.None);

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
        ZkInterfaceCursorDecoder.Decoder(new ReadOnlySequence<byte>(stream), sink, CancellationToken.None);

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
            ZkInterfaceCursorDecoder.Decoder(new ReadOnlySequence<byte>(stream), sink, CancellationToken.None));

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
            ZkInterfaceCursorDecoder.Decoder(new ReadOnlySequence<byte>(stream), sink, CancellationToken.None));

        Assert.Contains($"values length {IndivisibleValueByteCount} is not divisible by the {TwoVariableIds} variable id(s)", exception.Message, "the element-size divisibility guard must be what rejects the stream");
        Assert.IsEmpty(sink.Terms, "no term is pushed before the coefficient width is validated");
    }


    //Encodes an aliased ConstraintSystem of the given shape and asserts the decode-work budget
    //rejects it with its own message, so a mis-encoded buffer tripping a bounds check would fail
    //this test rather than pass for the wrong reason.
    private static void AssertAliasedConstraintSystemRejected(int constraintAliases, int idsPerConstraint, int coefficientByteWidth)
    {
        int valueByteCount = idsPerConstraint * coefficientByteWidth;
        int streamLength = AliasedConstraintSystemStreamLength(constraintAliases, idsPerConstraint, valueByteCount);
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(streamLength);
        ReadOnlyMemory<byte> stream = owner.Memory[..streamLength];
        WriteAliasedConstraintSystemStream(owner.Memory.Span[..streamLength], constraintAliases, idsPerConstraint, valueByteCount, valuesPresent: true);

        var sink = new RecordingSink();
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() =>
            ZkInterfaceCursorDecoder.Decoder(new ReadOnlySequence<byte>(stream), sink, CancellationToken.None));

        Assert.Contains("more work than its byte length", exception.Message, "the decode-work budget must be what rejects the aliased stream");
    }


    //The packed stream length for the aliased fixture, mirroring WriteAliasedConstraintSystemStream:
    //the size prefix, the fixed table/vtable framing, and the three data vectors (constraint
    //offsets, variable ids, coefficient values — the values vector holds valueByteCount bytes).
    private static int AliasedConstraintSystemStreamLength(int constraintAliases, int idsPerConstraint, int valueByteCount)
    {
        const int tablesAndVtablesBytes = 69;   //root uoffset + Root/ConstraintSystem/BilinearConstraint/Variables tables and their vtables.
        int constraintsVectorBytes = 4 + (4 * constraintAliases);
        int idsVectorBytes = 4 + (8 * idsPerConstraint);
        int valuesVectorBytes = 4 + valueByteCount;

        return SizePrefixBytes + tablesAndVtablesBytes + constraintsVectorBytes + idsVectorBytes + valuesVectorBytes;
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

        int k = constraintAliases;
        int l = idsPerConstraint;

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

        //VT_vars: [8][12][idsOff=4][valuesOff=8, or the absent marker 0 when valuesPresent is false].
        BinaryPrimitives.WriteUInt16LittleEndian(m[pVtVars..], 8);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtVars + 2)..], 12);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtVars + 4)..], 4);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtVars + 6)..], valuesPresent ? VariablesValuesFieldOffset : AbsentFieldOffset);
        BinaryPrimitives.WriteInt32LittleEndian(m[pTVars..], pTVars - pVtVars);
        BinaryPrimitives.WriteUInt32LittleEndian(m[(pTVars + 4)..], (uint)(pVIds - (pTVars + 4)));
        BinaryPrimitives.WriteUInt32LittleEndian(m[(pTVars + 8)..], (uint)(pVValues - (pTVars + 8)));

        //V_ids: length l (uint64 element count), then l ids. V_values: length valueByteCount (a
        //ubyte vector, so its length prefix is a byte count), then that many zero bytes — element
        //size resolves to valueByteCount / l.
        BinaryPrimitives.WriteUInt32LittleEndian(m[pVIds..], (uint)l);
        for(int i = 0; i < l; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(m[(pVIds + 4 + (8 * i))..], (ulong)i);
        }

        BinaryPrimitives.WriteUInt32LittleEndian(m[pVValues..], (uint)valueByteCount);

        //The 4-byte little-endian size prefix carries the message length.
        BinaryPrimitives.WriteUInt32LittleEndian(destination, (uint)messageLength);
    }


    /// <summary>
    /// Fills <paramref name="destination"/>, exactly <see cref="EmptyWitnessStreamBytes"/> bytes, with
    /// a single size-prefixed Witness message whose <c>assigned_variables</c> table holds an empty
    /// <c>variable_ids</c> vector and an empty values vector. Every table size, vtable size and field
    /// offset is derived from the widths of the FlatBuffers building blocks; the layout is packed and
    /// every offset points forward.
    /// </summary>
    private static void WriteEmptyAssignedVariablesWitnessStream(Span<byte> destination)
    {
        destination.Clear();

        //Widths of the FlatBuffers building blocks the layout is packed from.
        const int soffsetBytes = sizeof(int);
        const int uoffsetBytes = sizeof(uint);
        const int vectorLengthBytes = sizeof(uint);
        const int unionTypeBytes = sizeof(byte);
        const uint emptyVectorLength = 0;

        //Vtable entry offsets: the table inline size follows the vtable byte length, and the field
        //slots follow both header entries.
        const int tableBytesEntry = VtableEntryBytes;
        const int firstSlotEntry = VtableHeaderEntries * VtableEntryBytes;
        const int secondSlotEntry = firstSlotEntry + VtableEntryBytes;

        //Root holds its soffset, the union type byte and the union value uoffset; Witness holds its
        //soffset and the assigned_variables uoffset; Variables holds its soffset and the variable_ids
        //and values uoffsets. Each vtable carries its two header entries plus one entry per field.
        const int rootTypeFieldOffset = soffsetBytes;
        const int rootValueFieldOffset = rootTypeFieldOffset + unionTypeBytes;
        const int rootTableBytes = rootValueFieldOffset + uoffsetBytes;
        const int rootVtableBytes = secondSlotEntry + VtableEntryBytes;
        const int witnessAssignedFieldOffset = soffsetBytes;
        const int witnessTableBytes = witnessAssignedFieldOffset + uoffsetBytes;
        const int witnessVtableBytes = firstSlotEntry + VtableEntryBytes;
        const int variablesIdsFieldOffset = soffsetBytes;
        const int variablesTableBytes = VariablesValuesFieldOffset + uoffsetBytes;
        const int variablesVtableBytes = secondSlotEntry + VtableEntryBytes;

        //Positions relative to the message body, low -> high address. Each vtable sits immediately
        //before its table, and the two empty vectors close the message.
        const int pRootOffset = 0;
        const int pVtRoot = pRootOffset + uoffsetBytes;
        const int pTRoot = pVtRoot + rootVtableBytes;
        const int pVtWitness = pTRoot + rootTableBytes;
        const int pTWitness = pVtWitness + witnessVtableBytes;
        const int pVtVars = pTWitness + witnessTableBytes;
        const int pTVars = pVtVars + variablesVtableBytes;
        const int pVIds = pTVars + variablesTableBytes;
        const int pVValues = pVIds + vectorLengthBytes;
        const int messageLength = pVValues + vectorLengthBytes;

        //The message body follows the 4-byte size prefix.
        Span<byte> m = destination[SizePrefixBytes..];

        //Root uoffset -> T_root.
        BinaryPrimitives.WriteUInt32LittleEndian(m[pRootOffset..], pTRoot - pRootOffset);

        //VT_root declares the union type and value fields; T_root carries the Witness tag and a uoffset -> T_witness.
        BinaryPrimitives.WriteUInt16LittleEndian(m[pVtRoot..], rootVtableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtRoot + tableBytesEntry)..], rootTableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtRoot + firstSlotEntry)..], rootTypeFieldOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtRoot + secondSlotEntry)..], rootValueFieldOffset);
        BinaryPrimitives.WriteInt32LittleEndian(m[pTRoot..], pTRoot - pVtRoot);
        m[pTRoot + rootTypeFieldOffset] = (byte)ZkInterfaceMessageType.Witness;
        BinaryPrimitives.WriteUInt32LittleEndian(m[(pTRoot + rootValueFieldOffset)..], pTWitness - (pTRoot + rootValueFieldOffset));

        //VT_witness declares assigned_variables; T_witness carries a uoffset -> T_vars.
        BinaryPrimitives.WriteUInt16LittleEndian(m[pVtWitness..], witnessVtableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtWitness + tableBytesEntry)..], witnessTableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtWitness + firstSlotEntry)..], witnessAssignedFieldOffset);
        BinaryPrimitives.WriteInt32LittleEndian(m[pTWitness..], pTWitness - pVtWitness);
        BinaryPrimitives.WriteUInt32LittleEndian(m[(pTWitness + witnessAssignedFieldOffset)..], pTVars - (pTWitness + witnessAssignedFieldOffset));

        //VT_vars declares variable_ids and values; T_vars carries a uoffset to each vector.
        BinaryPrimitives.WriteUInt16LittleEndian(m[pVtVars..], variablesVtableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtVars + tableBytesEntry)..], variablesTableBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtVars + firstSlotEntry)..], variablesIdsFieldOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(m[(pVtVars + secondSlotEntry)..], VariablesValuesFieldOffset);
        BinaryPrimitives.WriteInt32LittleEndian(m[pTVars..], pTVars - pVtVars);
        BinaryPrimitives.WriteUInt32LittleEndian(m[(pTVars + variablesIdsFieldOffset)..], pVIds - (pTVars + variablesIdsFieldOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(m[(pTVars + VariablesValuesFieldOffset)..], pVValues - (pTVars + VariablesValuesFieldOffset));

        //Both vectors are empty: a zero element count and no element bytes.
        BinaryPrimitives.WriteUInt32LittleEndian(m[pVIds..], emptyVectorLength);
        BinaryPrimitives.WriteUInt32LittleEndian(m[pVValues..], emptyVectorLength);

        //The 4-byte little-endian size prefix carries the message length.
        BinaryPrimitives.WriteUInt32LittleEndian(destination, messageLength);
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

        Assert.AreSequenceEqual(expectedIds, ids, $"variable ids for constraint {constraintIndex} matrix {matrix}");
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
