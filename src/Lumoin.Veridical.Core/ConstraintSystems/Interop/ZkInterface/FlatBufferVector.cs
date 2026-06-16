using System;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// A read-only view over one FlatBuffers vector (or string) within a
/// message buffer.
/// </summary>
/// <remarks>
/// <para>
/// A FlatBuffers vector is a little-endian <see cref="uint"/> element
/// count followed by that many contiguous elements. The element width
/// depends on the element type, which the vector itself does not record;
/// callers pick the matching accessor: <see cref="ByteSpan"/> for
/// <c>[ubyte]</c> (and the raw bytes of a UTF-8 string),
/// <see cref="ElementUInt64"/> for <c>[uint64]</c>, and
/// <see cref="ElementTable"/> for a vector of sub-tables (each element is
/// a forward offset to a table).
/// </para>
/// </remarks>
internal readonly ref struct FlatBufferVector
{
    private readonly ReadOnlySpan<byte> buffer;
    private readonly int dataPosition;
    private readonly int length;


    private FlatBufferVector(ReadOnlySpan<byte> buffer, int dataPosition, int length)
    {
        this.buffer = buffer;
        this.dataPosition = dataPosition;
        this.length = length;
    }


    /// <summary>The element count.</summary>
    public int Length => length;


    /// <summary>
    /// Constructs a vector view from the position of its length prefix.
    /// </summary>
    public static FlatBufferVector At(ReadOnlySpan<byte> buffer, int vectorPosition)
    {
        uint rawLength = FlatBufferCursor.ReadUInt32(buffer, vectorPosition);
        int dataStart = vectorPosition + FlatBufferCursor.OffsetSize;
        if(rawLength > int.MaxValue || (long)dataStart + rawLength > buffer.Length)
        {
            //Cheapest sound upper bound: even a one-byte-per-element vector
            //cannot extend past the buffer. Wider element types are bounds-
            //checked again per element on access.
            throw new ArgumentException(
                $"FlatBuffers vector at {vectorPosition} declares {rawLength} elements, which overruns the {buffer.Length}-byte buffer.");
        }

        return new FlatBufferVector(buffer, dataStart, (int)rawLength);
    }


    /// <summary>
    /// The raw element bytes, interpreting the vector as <c>[ubyte]</c>
    /// (used for coefficient values, <c>field_maximum</c>, and string text).
    /// </summary>
    public ReadOnlySpan<byte> ByteSpan
    {
        get
        {
            //Length already validated against the buffer for the 1-byte case.
            return buffer.Slice(dataPosition, length);
        }
    }


    /// <summary>Reads element <paramref name="index"/> as a little-endian <see cref="ulong"/> (a <c>[uint64]</c> vector such as <c>variable_ids</c>).</summary>
    public ulong ElementUInt64(int index)
    {
        ThrowIfIndexOutOfRange(index);
        return FlatBufferCursor.ReadUInt64(buffer, dataPosition + index * sizeof(ulong));
    }


    /// <summary>
    /// Resolves element <paramref name="index"/> of a vector of sub-tables
    /// (each element is a forward offset to a table, such as a
    /// <c>BilinearConstraint</c> or a <c>KeyValue</c>).
    /// </summary>
    public FlatBufferTable ElementTable(int index)
    {
        ThrowIfIndexOutOfRange(index);
        int offsetPosition = dataPosition + index * FlatBufferCursor.OffsetSize;
        int tablePosition = FlatBufferCursor.FollowOffset(buffer, offsetPosition);
        return FlatBufferTable.At(buffer, tablePosition);
    }


    private void ThrowIfIndexOutOfRange(int index)
    {
        if(index < 0 || index >= length)
        {
            throw new ArgumentOutOfRangeException(
                nameof(index), index, $"FlatBuffers vector index out of range; the vector has {length} elements.");
        }
    }
}
