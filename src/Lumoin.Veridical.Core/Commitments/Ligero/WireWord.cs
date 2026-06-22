using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// A pooled, fixed-length vector of wire indices — the constraint-construction counterpart of a machine
/// word carried across the gadget surface. The backing bytes are rented from the
/// <see cref="LigeroConstraintSystemBuilder"/>'s arena (and so from the caller's pool, cleared and
/// accounted on the builder's disposal); this is a non-owning view over that arena slice, so the builder
/// owns the lifetime and releases every wire word together when the circuit build completes. Carrying the
/// indices as a named value rather than a naked <c>int[]</c> keeps the pooling explicit and the gadget
/// signatures self-describing.
/// </summary>
[DebuggerDisplay("WireWord: Length={Length}")]
internal readonly struct WireWord
{
    //The pooled arena slice; exactly Length * sizeof(int) bytes, reinterpreted as the wire indices. The
    //field is a value over pooled memory the builder owns — writing through Span mutates the buffer, not
    //this readonly struct, so a {0,1} indexer set is legal here.
    private readonly Memory<byte> backing;

    internal WireWord(Memory<byte> backing, int length)
    {
        this.backing = backing;
        Length = length;
    }


    /// <summary>The number of wire indices in this word.</summary>
    public int Length { get; }


    /// <summary>The wire indices as a span, reinterpreting the pooled backing bytes.</summary>
    public Span<int> Span => MemoryMarshal.Cast<byte, int>(backing.Span);


    /// <summary>The wire index at <paramref name="index"/>.</summary>
    public int this[int index]
    {
        get => Span[index];
        set => Span[index] = value;
    }


    /// <summary>
    /// A sub-view of <paramref name="length"/> wire indices starting at <paramref name="start"/>, sharing the
    /// same pooled backing (no copy). Used where a word's bits are consumed in groups — e.g. the eight bytes
    /// of a digest word fed to recomposition.
    /// </summary>
    public WireWord Slice(int start, int length) => new(backing.Slice(start * sizeof(int), length * sizeof(int)), length);


    /// <summary>
    /// Reads the wire indices as a read-only span. The implicit form lets a <see cref="WireWord"/> flow into
    /// the gadget surface's <see cref="ReadOnlySpan{T}"/> bit-vector parameters without an intermediate array.
    /// </summary>
    public static implicit operator ReadOnlySpan<int>(WireWord word) => word.Span;
}
