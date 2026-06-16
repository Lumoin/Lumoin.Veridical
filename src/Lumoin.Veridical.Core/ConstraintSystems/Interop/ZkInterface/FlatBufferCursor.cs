using System;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Bounds-checked primitive reads over a contiguous FlatBuffers buffer.
/// </summary>
/// <remarks>
/// <para>
/// The ZkInterface adapter parses the FlatBuffers binary wire format by
/// hand rather than depending on <c>Google.FlatBuffers</c>; serialization
/// dependencies are banned-by-default in this library. This type and the
/// companion <see cref="FlatBufferTable"/> / <see cref="FlatBufferVector"/>
/// cover exactly the slice of the format the schema at
/// <c>https://github.com/QED-it/zkinterface/blob/master/zkinterface.fbs</c>
/// uses: tables with vtables, scalar fields, vectors of scalars, vectors
/// of sub-tables, and table-to-table offsets. No structs, no enums-as-keys,
/// no nested buffers.
/// </para>
/// <para>
/// All multi-byte integers on the FlatBuffers wire are little-endian. Every
/// read validates its range against the buffer length and throws
/// <see cref="ArgumentException"/> on an out-of-range access, so a truncated
/// or malformed file surfaces as a descriptive parse error rather than an
/// <see cref="IndexOutOfRangeException"/>.
/// </para>
/// <para>
/// Positions are byte indices into a single FlatBuffers message buffer (the
/// payload of one size-prefixed message, with its root offset at index 0).
/// </para>
/// </remarks>
internal static class FlatBufferCursor
{
    /// <summary>The width, in bytes, of a FlatBuffers offset (uoffset / soffset / voffset base) used for tables, vectors, and strings.</summary>
    public const int OffsetSize = sizeof(uint);

    /// <summary>The width, in bytes, of a vtable entry (and the vtable's own size / table-size header fields).</summary>
    public const int VtableEntrySize = sizeof(ushort);


    /// <summary>Reads a single unsigned byte at <paramref name="position"/>.</summary>
    public static byte ReadByte(ReadOnlySpan<byte> buffer, int position)
    {
        EnsureRange(buffer, position, sizeof(byte), "byte");
        return buffer[position];
    }


    /// <summary>Reads a little-endian <see cref="ushort"/> at <paramref name="position"/> (vtable fields are stored this way).</summary>
    public static ushort ReadUInt16(ReadOnlySpan<byte> buffer, int position)
    {
        EnsureRange(buffer, position, sizeof(ushort), "uint16");
        return BinaryPrimitives.ReadUInt16LittleEndian(buffer.Slice(position));
    }


    /// <summary>Reads a little-endian <see cref="int"/> at <paramref name="position"/> (a table's signed offset to its vtable).</summary>
    public static int ReadInt32(ReadOnlySpan<byte> buffer, int position)
    {
        EnsureRange(buffer, position, sizeof(int), "int32");
        return BinaryPrimitives.ReadInt32LittleEndian(buffer.Slice(position));
    }


    /// <summary>Reads a little-endian <see cref="uint"/> at <paramref name="position"/> (an unsigned forward offset, or a vector length).</summary>
    public static uint ReadUInt32(ReadOnlySpan<byte> buffer, int position)
    {
        EnsureRange(buffer, position, sizeof(uint), "uint32");
        return BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(position));
    }


    /// <summary>Reads a little-endian <see cref="ulong"/> at <paramref name="position"/> (a variable ID, or <c>free_variable_id</c>).</summary>
    public static ulong ReadUInt64(ReadOnlySpan<byte> buffer, int position)
    {
        EnsureRange(buffer, position, sizeof(ulong), "uint64");
        return BinaryPrimitives.ReadUInt64LittleEndian(buffer.Slice(position));
    }


    /// <summary>
    /// Follows an unsigned forward offset (uoffset) stored at
    /// <paramref name="position"/> to the absolute index it points at.
    /// FlatBuffers offsets are relative to the location of the offset
    /// itself, not to the buffer start.
    /// </summary>
    public static int FollowOffset(ReadOnlySpan<byte> buffer, int position)
    {
        uint offset = ReadUInt32(buffer, position);
        long target = (long)position + offset;
        if(target < 0 || target > buffer.Length)
        {
            throw new ArgumentException(
                $"FlatBuffers offset at position {position} points to {target}, outside the {buffer.Length}-byte buffer.");
        }

        return (int)target;
    }


    private static void EnsureRange(ReadOnlySpan<byte> buffer, int position, int size, string fieldKind)
    {
        if(position < 0 || (long)position + size > buffer.Length)
        {
            throw new ArgumentException(
                $"FlatBuffers read of {fieldKind} ({size} bytes) at position {position} runs past the {buffer.Length}-byte buffer.");
        }
    }
}
