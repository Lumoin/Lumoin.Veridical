namespace Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Locates one message inside a ZkInterface byte stream: its union type
/// and the byte range of its FlatBuffers buffer within the whole file
/// (excluding the 4-byte size prefix). Holding the range rather than a
/// live <see cref="FlatBufferTable"/> keeps the inventory storable in an
/// ordinary list; a caller re-wraps the buffer with
/// <see cref="FlatBufferTable.Root"/> over the corresponding slice to read
/// the message contents.
/// </summary>
/// <param name="Type">The decoded <c>Root.message_type</c> discriminator.</param>
/// <param name="BufferStart">The index, into the whole file buffer, where this message's FlatBuffers buffer begins.</param>
/// <param name="BufferLength">The length of this message's FlatBuffers buffer in bytes.</param>
internal readonly record struct ZkInterfaceMessageSpan(
    ZkInterfaceMessageType Type,
    int BufferStart,
    int BufferLength);
