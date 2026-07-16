using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// The built-in <see cref="ZkInterfaceMessageDecoderDelegate"/>: it
/// hand-parses the ZkInterface FlatBuffers wire format with
/// <see cref="FlatBufferTable"/> / <see cref="FlatBufferVector"/> and
/// pushes the decoded fields into a sink. This is the default behind
/// <see cref="ZkInterfaceR1csReader.Reader"/>; substitute another
/// implementation via <see cref="ZkInterfaceR1csReader.CreateReader"/>.
/// </summary>
public static class ZkInterfaceCursorDecoder
{
    //Root.message is a union, occupying two consecutive vtable slots: the
    //discriminator byte, then the offset to the union value table.
    private const int RootMessageTypeSlot = 0;
    private const int RootMessageValueSlot = 1;

    //Schema-declaration slot order (zkinterface.fbs). A field's vtable slot
    //is its zero-based position in its table's field list.
    private const int HeaderInstanceVariablesSlot = 0;
    private const int HeaderFreeVariableIdSlot = 1;
    private const int HeaderFieldMaximumSlot = 2;

    private const int ConstraintSystemConstraintsSlot = 0;

    private const int ConstraintLcASlot = 0;
    private const int ConstraintLcBSlot = 1;
    private const int ConstraintLcCSlot = 2;

    private const int VariablesIdsSlot = 0;
    private const int VariablesValuesSlot = 1;

    private const int WitnessAssignedVariablesSlot = 0;

    //A 4-byte little-endian size precedes every message in the stream.
    private const int MessageSizePrefixBytes = sizeof(uint);


    /// <summary>The hand-written FlatBuffers decoder exposed as the swap-seam delegate.</summary>
    public static ZkInterfaceMessageDecoderDelegate Decoder { get; } = Decode;


    private static void Decode(ReadOnlySequence<byte> source, IZkInterfaceMessageSink sink, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sink);

        //FlatBuffers needs random access; use the segment directly when the
        //stream is contiguous, otherwise copy it into one buffer.
        if(source.IsSingleSegment)
        {
            DecodeContiguous(source.FirstSpan, sink, cancellationToken);
        }
        else
        {
            byte[] contiguous = source.ToArray();
            DecodeContiguous(contiguous, sink, cancellationToken);
        }
    }


    //Decodes one already-resolved message body (CircuitHeader, ConstraintSystem, or Witness)
    //into the sink under the shared work budget; the three body decoders share this shape so the
    //union discriminator can select one by pattern match.
    private delegate void MessageBodyDecoder(FlatBufferTable value, IZkInterfaceMessageSink sink, DecodeBudget budget);


    private static void DecodeContiguous(ReadOnlySpan<byte> file, IZkInterfaceMessageSink sink, CancellationToken cancellationToken)
    {
        IReadOnlyList<ZkInterfaceMessageSpan> messages = LocateMessages(file);

        //Bound the total decode work by the source length. FlatBuffers offsets are
        //attacker-controlled and may alias — many vector elements pointing at one
        //shared table — so a bounded-length message could otherwise re-expand the same
        //object to drive an unbounded, even quadratic, number of decoded events, and
        //re-scan one shared over-long coefficient across many terms for quadratic byte
        //work. The budget charges both axes — one unit per decoded event and one per
        //coefficient byte scanned — against the source length, so a valid stream stays
        //well under the ceiling while an aliasing amplification is rejected. This keeps
        //decode work linear in input for every sink, complementing the builders' own
        //allocation ceilings.
        var budget = new DecodeBudget(file.Length);

        foreach(ZkInterfaceMessageSpan message in messages)
        {
            cancellationToken.ThrowIfCancellationRequested();

            ReadOnlySpan<byte> buffer = file.Slice(message.BufferStart, message.BufferLength);
            FlatBufferTable root = FlatBufferTable.Root(buffer);
            if(!root.TryGetSubTable(RootMessageValueSlot, out FlatBufferTable value))
            {
                //LocateMessages already rejects a missing union value; this
                //keeps the dispatch total without an unguarded dereference.
                continue;
            }

            //The union discriminator selects the body decoder; a null step ignores
            //Command (gadget-flow control), which the R1CS reader does not interpret.
            MessageBodyDecoder? decodeBody = message.Type switch
            {
                ZkInterfaceMessageType.CircuitHeader => DecodeCircuitHeader,
                ZkInterfaceMessageType.ConstraintSystem => DecodeConstraintSystem,
                ZkInterfaceMessageType.Witness => DecodeWitness,
                _ => null,
            };

            decodeBody?.Invoke(value, sink, budget);
        }
    }


    /// <summary>
    /// Walks the size-prefixed message stream and classifies each message by
    /// its <c>Root.message_type</c> union discriminator, returning the byte
    /// range of every message's FlatBuffers buffer in stream order. This is
    /// the framing step: it validates size prefixes, message bounds, and the
    /// trailing-bytes invariant without interpreting message contents.
    /// </summary>
    internal static IReadOnlyList<ZkInterfaceMessageSpan> LocateMessages(ReadOnlySpan<byte> file)
    {
        var messages = new List<ZkInterfaceMessageSpan>();

        int position = 0;
        int messageIndex = 0;
        while(position < file.Length)
        {
            if(position + MessageSizePrefixBytes > file.Length)
            {
                throw new ArgumentException(
                    $"ZkInterface stream has {file.Length - position} trailing byte(s) after message {messageIndex - 1}; too few for a {MessageSizePrefixBytes}-byte size prefix.");
            }

            uint messageSize = BinaryPrimitives.ReadUInt32LittleEndian(file.Slice(position));
            int bufferStart = position + MessageSizePrefixBytes;

            if(messageSize == 0)
            {
                throw new ArgumentException($"ZkInterface message {messageIndex} declares a zero-byte size.");
            }

            if((long)bufferStart + messageSize > file.Length)
            {
                throw new ArgumentException(
                    $"ZkInterface message {messageIndex} declares size {messageSize} bytes but only {file.Length - bufferStart} bytes remain in the stream.");
            }

            int bufferLength = (int)messageSize;
            ReadOnlySpan<byte> messageBuffer = file.Slice(bufferStart, bufferLength);

            FlatBufferTable root = FlatBufferTable.Root(messageBuffer);
            var messageType = (ZkInterfaceMessageType)root.ReadByteField(RootMessageTypeSlot, (byte)ZkInterfaceMessageType.None);

            bool hasValue = root.HasField(RootMessageValueSlot);
            if(messageType == ZkInterfaceMessageType.None || !hasValue)
            {
                throw new ArgumentException(
                    $"ZkInterface message {messageIndex} has an empty or inconsistent Root.message union (type {(byte)messageType}, value present: {hasValue}).");
            }

            messages.Add(new ZkInterfaceMessageSpan(messageType, bufferStart, bufferLength));

            position = bufferStart + bufferLength;
            messageIndex++;
        }

        if(messages.Count == 0)
        {
            throw new ArgumentException("ZkInterface stream contains no messages.");
        }

        return messages;
    }


    private static void DecodeCircuitHeader(FlatBufferTable header, IZkInterfaceMessageSink sink, DecodeBudget budget)
    {
        sink.OnFreeVariableId(header.ReadUInt64Field(HeaderFreeVariableIdSlot));

        if(header.TryGetVector(HeaderFieldMaximumSlot, out FlatBufferVector fieldMaximum))
        {
            sink.OnFieldMaximum(fieldMaximum.ByteSpan);
        }

        if(header.TryGetSubTable(HeaderInstanceVariablesSlot, out FlatBufferTable instanceVariables))
        {
            DecodeAssignments(instanceVariables, sink, witness: false, budget);
        }
    }


    private static void DecodeConstraintSystem(FlatBufferTable system, IZkInterfaceMessageSink sink, DecodeBudget budget)
    {
        if(!system.TryGetVector(ConstraintSystemConstraintsSlot, out FlatBufferVector constraints))
        {
            return;
        }

        for(int i = 0; i < constraints.Length; i++)
        {
            //Spend before decoding each constraint so an aliased constraints vector — every
            //offset element pointing at one shared table — cannot re-run this loop past the
            //source length.
            budget.SpendEvent();

            FlatBufferTable constraint = constraints.ElementTable(i);
            sink.BeginConstraint();
            DecodeLinearCombination(constraint, ConstraintLcASlot, ZkInterfaceConstraintMatrix.A, sink, budget);
            DecodeLinearCombination(constraint, ConstraintLcBSlot, ZkInterfaceConstraintMatrix.B, sink, budget);
            DecodeLinearCombination(constraint, ConstraintLcCSlot, ZkInterfaceConstraintMatrix.C, sink, budget);
            sink.EndConstraint();
        }
    }


    private static void DecodeWitness(FlatBufferTable witness, IZkInterfaceMessageSink sink, DecodeBudget budget)
    {
        if(witness.TryGetSubTable(WitnessAssignedVariablesSlot, out FlatBufferTable assigned))
        {
            DecodeAssignments(assigned, sink, witness: true, budget);
        }
    }


    private static void DecodeAssignments(FlatBufferTable variables, IZkInterfaceMessageSink sink, bool witness, DecodeBudget budget)
    {
        if(!variables.TryGetVector(VariablesIdsSlot, out FlatBufferVector ids) || ids.Length == 0)
        {
            return;
        }

        bool hasValues = variables.TryGetVector(VariablesValuesSlot, out FlatBufferVector values);
        ReadOnlySpan<byte> valueBytes = hasValues ? values.ByteSpan : default;
        int elementSize = 0;
        if(hasValues)
        {
            elementSize = ElementSize(valueBytes.Length, ids.Length);
        }

        for(int i = 0; i < ids.Length; i++)
        {
            //Spend before each assignment: one event so an aliased assigned_variables table
            //cannot push more values than the source length across all messages, and the value
            //bytes so an over-long assignment coefficient cannot drive scan work past the input.
            budget.SpendEvent();
            budget.SpendScan(elementSize);

            ulong id = ids.ElementUInt64(i);
            ReadOnlySpan<byte> value = hasValues ? valueBytes.Slice(i * elementSize, elementSize) : default;
            if(witness)
            {
                sink.OnWitnessVariable(id, value);
            }
            else
            {
                sink.OnInstanceVariable(id, value);
            }
        }
    }


    private static void DecodeLinearCombination(
        FlatBufferTable constraint,
        int slot,
        ZkInterfaceConstraintMatrix matrix,
        IZkInterfaceMessageSink sink,
        DecodeBudget budget)
    {
        //An absent linear combination contributes no terms (a zero row).
        if(!constraint.TryGetSubTable(slot, out FlatBufferTable combination))
        {
            return;
        }

        if(!combination.TryGetVector(VariablesIdsSlot, out FlatBufferVector ids) || ids.Length == 0)
        {
            return;
        }

        if(!combination.TryGetVector(VariablesValuesSlot, out FlatBufferVector values))
        {
            throw new ArgumentException("ZkInterface linear combination has variable_ids but no coefficient values.");
        }

        ReadOnlySpan<byte> valueBytes = values.ByteSpan;
        int elementSize = ElementSize(valueBytes.Length, ids.Length);

        for(int i = 0; i < ids.Length; i++)
        {
            //Spend before each term: one event so an aliased ids vector shared across many
            //constraints cannot append O(constraints x ids) triples from a linear-sized
            //message, and the coefficient bytes so re-reading one shared over-long coefficient
            //across aliased constraints cannot drive quadratic scan work under the event count.
            budget.SpendEvent();
            budget.SpendScan(elementSize);

            sink.OnConstraintTerm(matrix, ids.ElementUInt64(i), valueBytes.Slice(i * elementSize, elementSize));
        }
    }


    private static int ElementSize(int valueByteCount, int idCount)
    {
        //Per the schema: element size = values.length / variable_ids.length.
        if(valueByteCount % idCount != 0)
        {
            throw new ArgumentException(
                $"ZkInterface variables: values length {valueByteCount} is not divisible by the {idCount} variable id(s).");
        }

        return valueByteCount / idCount;
    }


    /// <summary>
    /// A decode-work budget: the total decode work one stream may drive is capped at
    /// its own byte length. Work is charged on two axes — one unit per decoded event
    /// (a constraint, a constraint term, or a variable assignment) and one unit per
    /// coefficient/value byte a term or assignment hands the sink to scan. Because a
    /// genuine event costs several source bytes (a constraint is a 4-byte offset
    /// element, a variable id an 8-byte vector element) and a genuine coefficient is
    /// physically present once, a well-formed stream's charge sits comfortably below
    /// its length; a stream that exceeds it is re-expanding aliased offsets — the same
    /// bytes decoded or re-scanned many times — and is turned away before the
    /// amplification can grow a sink's buffers or spend super-linear scan time.
    /// </summary>
    private sealed class DecodeBudget
    {
        private long remaining;


        public DecodeBudget(int sourceByteLength)
        {
            remaining = sourceByteLength;
        }


        //Charge one decoded event (a constraint, a term, or an assignment), bounding
        //the number of decoded events by the source byte length.
        public void SpendEvent() => Spend(1);


        //Charge the coefficient/value bytes a term or assignment hands to the sink,
        //bounding the total scan work by the source byte length. An aliased vector whose
        //over-long coefficient is re-read across many terms exhausts the budget here
        //rather than driving quadratic scan work through the canonical-scalar writer.
        public void SpendScan(int byteCount) => Spend(byteCount);


        private void Spend(long units)
        {
            remaining -= units;
            if(remaining < 0)
            {
                throw new ArgumentException(
                    "ZkInterface stream decodes more work than its byte length can account for; rejecting a likely offset-aliasing amplification.");
            }
        }
    }
}
