using System;
using System.Buffers;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>Owns stable byte slices for a compiler, scheduler or sumcheck circuit.</summary>
/// <remarks>All slices are borrowed until disposal. The supplying pool must outlive this owner.</remarks>
internal sealed class LongfellowCircuitStorage: IDisposable
{
    /// <summary>A slab holds 128 scalar-sized values to amortize retained coefficient rentals.</summary>
    private const int SlabBytes = 4096;

    /// <summary>The pool supplying this owner's slabs.</summary>
    private BaseMemoryPool Pool { get; }

    /// <summary>The sensitive owners of every allocated slab.</summary>
    private List<Slab> Slabs { get; } = [];

    /// <summary>The unallocated portion of the latest slab.</summary>
    private Memory<byte> remaining;

    /// <summary>Whether all owned slabs have been released.</summary>
    private bool isDisposed;

    /// <summary>Constructs an empty owner using the supplied pool.</summary>
    /// <param name="pool">The pool supplying retained bytes.</param>
    public LongfellowCircuitStorage(BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        this.Pool = pool;
    }

    /// <summary>Returns a zero-filled, stable slice owned until disposal; empty slices need no rental.</summary>
    /// <param name="length">The logical byte length.</param>
    /// <returns>The writable slice.</returns>
    public Memory<byte> Allocate(int length)
    {
        ObjectDisposedException.ThrowIf(isDisposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        if(length == 0)
        {
            return Memory<byte>.Empty;
        }

        if(remaining.Length < length)
        {
            IMemoryOwner<byte>? owner = Pool.Rent(Math.Max(SlabBytes, length));
            Slab? slab = null;
            try
            {
                slab = new Slab(owner);
                owner = null;
                Slabs.Add(slab);
                remaining = slab.Bytes;
                slab = null;
            }
            finally
            {
                slab?.Dispose();
                owner?.Dispose();
            }
        }

        Memory<byte> bytes = remaining[..length];
        remaining = remaining[length..];
        bytes.Span.Clear();

        return bytes;
    }

    /// <summary>Copies bytes into a stable owned slice, including the empty case.</summary>
    /// <param name="source">The bytes to copy.</param>
    /// <returns>The independent copy.</returns>
    public Memory<byte> Copy(ReadOnlySpan<byte> source)
    {
        Memory<byte> bytes = Allocate(source.Length);
        source.CopyTo(bytes.Span);

        return bytes;
    }

    /// <summary>Clears and releases all slabs. Repeated disposal has no effect.</summary>
    public void Dispose()
    {
        if(isDisposed)
        {
            return;
        }

        isDisposed = true;
        remaining = Memory<byte>.Empty;
        foreach(Slab slab in Slabs)
        {
            slab.Dispose();
        }

        Slabs.Clear();
    }

    /// <summary>A sensitive slab whose writable view is available only to its enclosing owner.</summary>
    private sealed class Slab: SensitiveMemory
    {
        /// <summary>Takes ownership of the supplied rental.</summary>
        /// <param name="owner">The positive-length rental.</param>
        public Slab(IMemoryOwner<byte> owner): base(owner, Tag.Empty)
        {
        }

        /// <summary>The slab's writable storage.</summary>
        public Memory<byte> Bytes => MemoryOwner.Memory;
    }
}
