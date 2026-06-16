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


    private static void DecodeContiguous(ReadOnlySpan<byte> file, IZkInterfaceMessageSink sink, CancellationToken cancellationToken)
    {
        IReadOnlyList<ZkInterfaceMessageSpan> messages = LocateMessages(file);

        foreach(ZkInterfaceMessageSpan message in messages)
        {
            cancellationToken.ThrowIfCancellationRequested();

            ReadOnlySpan<byte> buffer = file.Slice(message.BufferStart, message.BufferLength);
            FlatBufferTable root = FlatBufferTable.Root(buffer);
            if(!root.TryGetSubTable(RootMessageValueSlot, out FlatBufferTable value))
            {
                //LocateMessages already rejects a missing union value; this
                //keeps the switch total without an unguarded dereference.
                continue;
            }

            switch(message.Type)
            {
                case ZkInterfaceMessageType.CircuitHeader:
                    DecodeCircuitHeader(value, sink);
                    break;

                case ZkInterfaceMessageType.ConstraintSystem:
                    DecodeConstraintSystem(value, sink);
                    break;

                case ZkInterfaceMessageType.Witness:
                    DecodeWitness(value, sink);
                    break;

                //Command (gadget-flow control) is not interpreted by the R1CS reader.
                default:
                    break;
            }
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


    private static void DecodeCircuitHeader(FlatBufferTable header, IZkInterfaceMessageSink sink)
    {
        sink.OnFreeVariableId(header.ReadUInt64Field(HeaderFreeVariableIdSlot));

        if(header.TryGetVector(HeaderFieldMaximumSlot, out FlatBufferVector fieldMaximum))
        {
            sink.OnFieldMaximum(fieldMaximum.ByteSpan);
        }

        if(header.TryGetSubTable(HeaderInstanceVariablesSlot, out FlatBufferTable instanceVariables))
        {
            DecodeAssignments(instanceVariables, sink, witness: false);
        }
    }


    private static void DecodeConstraintSystem(FlatBufferTable system, IZkInterfaceMessageSink sink)
    {
        if(!system.TryGetVector(ConstraintSystemConstraintsSlot, out FlatBufferVector constraints))
        {
            return;
        }

        for(int i = 0; i < constraints.Length; i++)
        {
            FlatBufferTable constraint = constraints.ElementTable(i);
            sink.BeginConstraint();
            DecodeLinearCombination(constraint, ConstraintLcASlot, ZkInterfaceConstraintMatrix.A, sink);
            DecodeLinearCombination(constraint, ConstraintLcBSlot, ZkInterfaceConstraintMatrix.B, sink);
            DecodeLinearCombination(constraint, ConstraintLcCSlot, ZkInterfaceConstraintMatrix.C, sink);
            sink.EndConstraint();
        }
    }


    private static void DecodeWitness(FlatBufferTable witness, IZkInterfaceMessageSink sink)
    {
        if(witness.TryGetSubTable(WitnessAssignedVariablesSlot, out FlatBufferTable assigned))
        {
            DecodeAssignments(assigned, sink, witness: true);
        }
    }


    private static void DecodeAssignments(FlatBufferTable variables, IZkInterfaceMessageSink sink, bool witness)
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
        IZkInterfaceMessageSink sink)
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
}
