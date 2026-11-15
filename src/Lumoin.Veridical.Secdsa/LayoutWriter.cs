using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The buffer a layout encoder writes into. An algorithm hands one to a <see cref="SecdsaLayoutProfile"/> encoder,
/// the encoder appends the fields of the structure in the profile's order and widths, and the algorithm hashes or
/// signs the written bytes. The writer grows by renting a larger buffer from its pool and clearing the one it
/// replaces, and clears its buffer when disposed, because the structures it holds may contain secrets such as the
/// ephemeral private keys.
/// </summary>
/// <remarks>
/// <para>
/// The writer is the only place bytes of a layout are assembled. Algorithms never concatenate fields, so a
/// different profile changes the bytes without touching an algorithm.
/// </para>
/// <para>
/// <b>Bound.</b> A single structure is bounded by <see cref="MaxLengthBytes"/>; an encoder that would exceed it
/// gets an <see cref="InvalidOperationException"/>, so an oversized or hostile field cannot drive unbounded
/// allocation.
/// </para>
/// </remarks>
public sealed class LayoutWriter: IDisposable
{
    /// <summary>The largest structure a writer holds: one mebibyte.</summary>
    public const int MaxLengthBytes = 1 << 20;

    private const int DefaultInitialCapacityBytes = 256;

    private BaseMemoryPool Pool { get; }

    private IMemoryOwner<byte>? Owner { get; set; }

    private int Capacity { get; set; }


    /// <summary>The number of bytes written so far.</summary>
    public int Length { get; private set; }


    /// <summary>Creates a writer that rents its buffer from <paramref name="pool"/>.</summary>
    /// <param name="pool">The pool to rent from.</param>
    /// <param name="initialCapacityBytes">The initial capacity, positive.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="initialCapacityBytes"/> is not positive or exceeds <see cref="MaxLengthBytes"/>.</exception>
    public LayoutWriter(BaseMemoryPool pool, int initialCapacityBytes = DefaultInitialCapacityBytes)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(initialCapacityBytes);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(initialCapacityBytes, MaxLengthBytes);

        Pool = pool;
        Capacity = initialCapacityBytes;
        Owner = pool.Rent(initialCapacityBytes);
    }


    /// <summary>The bytes written so far.</summary>
    /// <exception cref="ObjectDisposedException">When the writer has been disposed.</exception>
    public ReadOnlySpan<byte> WrittenBytes
    {
        get
        {
            ObjectDisposedException.ThrowIf(Owner is null, this);

            return Owner.Memory.Span[..Length];
        }
    }


    /// <summary>Appends bytes.</summary>
    /// <param name="bytes">The bytes to append.</param>
    /// <exception cref="InvalidOperationException">When the structure would exceed <see cref="MaxLengthBytes"/>.</exception>
    /// <exception cref="ObjectDisposedException">When the writer has been disposed.</exception>
    public void Append(ReadOnlySpan<byte> bytes)
    {
        Span<byte> destination = Reserve(bytes.Length);
        bytes.CopyTo(destination);
    }


    /// <summary>Appends one byte.</summary>
    /// <param name="value">The byte.</param>
    /// <exception cref="InvalidOperationException">When the structure would exceed <see cref="MaxLengthBytes"/>.</exception>
    /// <exception cref="ObjectDisposedException">When the writer has been disposed.</exception>
    public void AppendByte(byte value)
    {
        Reserve(sizeof(byte))[0] = value;
    }


    /// <summary>Appends a 16-bit unsigned integer, big-endian.</summary>
    /// <param name="value">The value.</param>
    /// <exception cref="InvalidOperationException">When the structure would exceed <see cref="MaxLengthBytes"/>.</exception>
    /// <exception cref="ObjectDisposedException">When the writer has been disposed.</exception>
    public void AppendUInt16BigEndian(ushort value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(Reserve(sizeof(ushort)), value);
    }


    /// <summary>Appends a 32-bit unsigned integer, big-endian.</summary>
    /// <param name="value">The value.</param>
    /// <exception cref="InvalidOperationException">When the structure would exceed <see cref="MaxLengthBytes"/>.</exception>
    /// <exception cref="ObjectDisposedException">When the writer has been disposed.</exception>
    public void AppendUInt32BigEndian(uint value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(Reserve(sizeof(uint)), value);
    }


    /// <summary>Clears the written bytes and returns the buffer to the pool.</summary>
    public void Dispose()
    {
        if(Owner is null)
        {
            return;
        }

        Owner.Memory.Span.Clear();
        Owner.Dispose();
        Owner = null;
        Length = 0;
    }


    private Span<byte> Reserve(int count)
    {
        ObjectDisposedException.ThrowIf(Owner is null, this);
        if(count > MaxLengthBytes - Length)
        {
            throw new InvalidOperationException($"A layout structure must not exceed {MaxLengthBytes} bytes.");
        }

        int required = Length + count;
        if(required > Capacity)
        {
            int grown = (int)Math.Min((long)MaxLengthBytes, Math.Max((long)required, (long)Capacity * 2));
            IMemoryOwner<byte> larger = Pool.Rent(grown);
            Owner.Memory.Span[..Length].CopyTo(larger.Memory.Span);
            Owner.Memory.Span.Clear();
            Owner.Dispose();
            Owner = larger;
            Capacity = grown;
        }

        Span<byte> destination = Owner.Memory.Span.Slice(Length, count);
        Length = required;

        return destination;
    }
}
