using System;
using System.Buffers;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// Presents a <see cref="LayoutWriter"/> as the <see cref="IBufferWriter{T}"/> that the CBOR writer of
/// Lumoin.Veritas.Cbor emits into, so CBOR output lands directly in the pooled, clearing buffer of the layout
/// writer and no intermediate array holds it.
/// </summary>
internal sealed class LayoutBufferWriter: IBufferWriter<byte>
{
    private LayoutWriter Target { get; }


    /// <summary>Creates an adapter over <paramref name="target"/>.</summary>
    /// <param name="target">The layout writer that receives the bytes.</param>
    internal LayoutBufferWriter(LayoutWriter target)
    {
        ArgumentNullException.ThrowIfNull(target);
        Target = target;
    }


    /// <inheritdoc/>
    public void Advance(int count) => Target.Advance(count);


    /// <inheritdoc/>
    public Memory<byte> GetMemory(int sizeHint = 0) => Target.GetMemory(sizeHint);


    /// <inheritdoc/>
    public Span<byte> GetSpan(int sizeHint = 0) => Target.GetMemory(sizeHint).Span;
}
