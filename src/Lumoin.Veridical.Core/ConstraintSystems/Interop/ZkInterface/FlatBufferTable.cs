using System;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// A read-only view over one FlatBuffers table within a message buffer.
/// </summary>
/// <remarks>
/// <para>
/// A FlatBuffers table is two parts. At the table's own position sits a
/// signed offset (soffset) to its vtable. The vtable is a list of
/// little-endian <see cref="ushort"/> entries: entry 0 is the vtable's
/// byte length, entry 1 is the table's inline size, and the remaining
/// entries — one per field slot, in schema-declaration order — give the
/// byte offset of that field within the table, or zero when the field is
/// absent and the reader should fall back to the schema default. Trailing
/// absent fields are simply omitted from the vtable, so a vtable can be
/// shorter than the schema's field count.
/// </para>
/// <para>
/// Scalar fields live inline at <c>table position + field offset</c>.
/// Table, vector, and string fields store an unsigned forward offset
/// (uoffset) there instead, pointing onward to the referenced object.
/// </para>
/// </remarks>
internal readonly ref struct FlatBufferTable
{
    private readonly ReadOnlySpan<byte> buffer;
    private readonly int position;


    private FlatBufferTable(ReadOnlySpan<byte> buffer, int position)
    {
        this.buffer = buffer;
        this.position = position;
    }


    /// <summary>The buffer this table reads from.</summary>
    public ReadOnlySpan<byte> Buffer => buffer;

    /// <summary>The absolute byte index of the table within the buffer.</summary>
    public int Position => position;


    /// <summary>
    /// Resolves the root table of a FlatBuffers message buffer: the buffer
    /// begins with a uoffset (at index 0) pointing to the root table.
    /// </summary>
    public static FlatBufferTable Root(ReadOnlySpan<byte> buffer)
    {
        int rootPosition = FlatBufferCursor.FollowOffset(buffer, 0);
        return new FlatBufferTable(buffer, rootPosition);
    }


    /// <summary>
    /// Wraps the table that begins at the already-resolved absolute
    /// <paramref name="position"/> (the target of a followed offset).
    /// </summary>
    public static FlatBufferTable At(ReadOnlySpan<byte> buffer, int position)
    {
        if(position < 0 || position + FlatBufferCursor.OffsetSize > buffer.Length)
        {
            throw new ArgumentException(
                $"FlatBuffers table position {position} lies outside the {buffer.Length}-byte buffer.");
        }

        return new FlatBufferTable(buffer, position);
    }


    /// <summary>
    /// Returns the absolute position of the field in slot
    /// <paramref name="slot"/> (schema-declaration order, zero-based), or
    /// <c>-1</c> when the field is absent and the schema default applies.
    /// </summary>
    public int FieldPosition(int slot)
    {
        int soffset = FlatBufferCursor.ReadInt32(buffer, position);
        int vtablePosition = position - soffset;
        if(vtablePosition < 0 || vtablePosition + 2 * FlatBufferCursor.VtableEntrySize > buffer.Length)
        {
            throw new ArgumentException(
                $"FlatBuffers table at {position} resolves a vtable position {vtablePosition} outside the {buffer.Length}-byte buffer.");
        }

        ushort vtableSize = FlatBufferCursor.ReadUInt16(buffer, vtablePosition);
        int slotEntry = vtablePosition + (2 + slot) * FlatBufferCursor.VtableEntrySize;

        //A vtable omits trailing absent fields, so an entry beyond the
        //declared vtable length means "absent — use the default".
        if(slot < 0 || slotEntry + FlatBufferCursor.VtableEntrySize > vtablePosition + vtableSize)
        {
            return -1;
        }

        ushort fieldOffset = FlatBufferCursor.ReadUInt16(buffer, slotEntry);
        if(fieldOffset == 0)
        {
            return -1;
        }

        return position + fieldOffset;
    }


    /// <summary>Whether the field in <paramref name="slot"/> is present in this table.</summary>
    public bool HasField(int slot) => FieldPosition(slot) >= 0;


    /// <summary>
    /// Reads an inline unsigned-byte field (for example a union
    /// discriminator), returning <paramref name="defaultValue"/> when the
    /// field is absent.
    /// </summary>
    public byte ReadByteField(int slot, byte defaultValue = 0)
    {
        int fieldPosition = FieldPosition(slot);
        return fieldPosition < 0 ? defaultValue : FlatBufferCursor.ReadByte(buffer, fieldPosition);
    }


    /// <summary>
    /// Reads an inline unsigned 64-bit field (for example
    /// <c>free_variable_id</c>), returning <paramref name="defaultValue"/>
    /// when the field is absent.
    /// </summary>
    public ulong ReadUInt64Field(int slot, ulong defaultValue = 0)
    {
        int fieldPosition = FieldPosition(slot);
        return fieldPosition < 0 ? defaultValue : FlatBufferCursor.ReadUInt64(buffer, fieldPosition);
    }


    /// <summary>
    /// Follows the table-valued field in <paramref name="slot"/> to its
    /// sub-table. Returns <see langword="false"/> when the field is absent.
    /// </summary>
    public bool TryGetSubTable(int slot, out FlatBufferTable subTable)
    {
        int fieldPosition = FieldPosition(slot);
        if(fieldPosition < 0)
        {
            subTable = default;
            return false;
        }

        int subTablePosition = FlatBufferCursor.FollowOffset(buffer, fieldPosition);
        subTable = new FlatBufferTable(buffer, subTablePosition);
        return true;
    }


    /// <summary>
    /// Follows the vector-valued (or string-valued) field in
    /// <paramref name="slot"/> to its contents. Returns
    /// <see langword="false"/> when the field is absent.
    /// </summary>
    public bool TryGetVector(int slot, out FlatBufferVector vector)
    {
        int fieldPosition = FieldPosition(slot);
        if(fieldPosition < 0)
        {
            vector = default;
            return false;
        }

        int vectorPosition = FlatBufferCursor.FollowOffset(buffer, fieldPosition);
        vector = FlatBufferVector.At(buffer, vectorPosition);
        return true;
    }
}
