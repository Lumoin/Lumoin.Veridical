using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Memory;

/// <summary>Owns a logical byte buffer backed by sensitive pooled storage.</summary>
/// <remarks>The supplying pool must outlive this owner and all borrowed views.</remarks>
internal sealed class OwnedByteBuffer: SensitiveMemory
{
    /// <summary>The logical length, excluding unused rental capacity.</summary>
    private int Length { get; }

    /// <summary>Takes ownership of a rental with the specified logical length.</summary>
    /// <param name="owner">The positive-length rental.</param>
    /// <param name="length">The number of bytes in the logical buffer.</param>
    private OwnedByteBuffer(IMemoryOwner<byte> owner, int length): base(owner, Tag.Empty)
    {
        this.Length = length;
    }

    /// <summary>Returns a writable borrow valid until disposal.</summary>
    public Span<byte> Bytes => MemoryOwner.Memory.Span[..Length];

    /// <summary>Rents a positive-length buffer and transfers its ownership.</summary>
    /// <param name="length">The positive logical byte length.</param>
    /// <param name="pool">The pool supplying the storage.</param>
    /// <returns>The buffer, which the caller must dispose.</returns>
    public static OwnedByteBuffer Rent(int length, BaseMemoryPool pool)
    {
        IMemoryOwner<byte>? owner = pool.Rent(length);
        try
        {
            OwnedByteBuffer buffer = new(owner, length);
            owner = null;

            return buffer;
        }
        finally
        {
            owner?.Dispose();
        }
    }
}
