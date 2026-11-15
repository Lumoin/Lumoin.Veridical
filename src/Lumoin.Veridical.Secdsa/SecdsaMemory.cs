using System;
using System.Buffers;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// Pooled-memory helpers shared by the SECDSA value types. A pool rents only positive lengths, while several
/// protocol values (empty additional data, an empty plaintext) are legitimately zero-length, so the empty case maps
/// to the shared empty owner and never reaches the pool.
/// </summary>
internal static class SecdsaMemory
{
    /// <summary>Copies a span into a fresh rental; a zero-length span maps to the shared empty owner.</summary>
    /// <param name="source">The bytes to copy.</param>
    /// <param name="pool">The pool to rent from.</param>
    /// <returns>An owner whose memory holds exactly the copied bytes.</returns>
    internal static IMemoryOwner<byte> CopyOf(ReadOnlySpan<byte> source, BaseMemoryPool pool)
    {
        if(source.IsEmpty)
        {
            return EmptyMemoryOwner.Instance;
        }

        IMemoryOwner<byte> owner = pool.Rent(source.Length);
        source.CopyTo(owner.Memory.Span);

        return owner;
    }


    /// <summary>Rents a buffer of the given length; a zero length maps to the shared empty owner.</summary>
    /// <param name="length">The length in bytes, zero or more.</param>
    /// <param name="pool">The pool to rent from.</param>
    /// <returns>An owner whose memory is exactly <paramref name="length"/> bytes.</returns>
    internal static IMemoryOwner<byte> Rent(int length, BaseMemoryPool pool)
    {
        return length == 0 ? EmptyMemoryOwner.Instance : pool.Rent(length);
    }
}
