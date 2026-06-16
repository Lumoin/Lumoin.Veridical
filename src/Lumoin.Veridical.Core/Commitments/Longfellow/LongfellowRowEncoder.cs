using System;
using System.Diagnostics;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// A field-tagged handle to a systematic Reed–Solomon row encoder: the threaded
/// <see cref="RowInterpolateDelegate"/> that extends a tableau row, together with the pooled precompute it
/// borrows and must release. The wire-format Ligero commit constructs one of these per <c>(N, M)</c> shape
/// (the reference's <c>RSFactory::make(n, m)</c>), extends every tableau row through it, and disposes it.
/// </summary>
/// <remarks>
/// The wrapper unifies the two fields without a type hierarchy: the binary hash circuit closes the delegate
/// over an <see cref="Algebraic.Lch14ReedSolomon"/> (which borrows the shared additive-FFT engine and owns
/// nothing, so <see cref="Dispose"/> releases nothing), while the prime signature circuit closes it over an
/// <see cref="Algebraic.Fp256ReedSolomon"/> whose per-<c>(N, M)</c> precompute (binomial weights, leading
/// constants, the FFT twiddle table) is pooled and handed in as <c>state</c> for disposal. The
/// <see cref="Tag"/> and the dimensions are carried for diagnostics; the commit itself reads neither.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplayValue,nq}")]
internal sealed class LongfellowRowEncoder: IDisposable
{
    private readonly RowInterpolateDelegate interpolate;
    private IDisposable? state;


    /// <summary>
    /// Wraps an <paramref name="interpolate"/> operation tagged <paramref name="tag"/> for the given
    /// dimensions, owning <paramref name="state"/> (the pooled precompute, or <see langword="null"/> for a
    /// stateless encoder).
    /// </summary>
    /// <param name="tag">A human-readable label of which field's encoder this wraps (diagnostics only).</param>
    /// <param name="dimension">The message length <c>N</c>.</param>
    /// <param name="blockLength">The codeword length <c>M</c>.</param>
    /// <param name="interpolate">The row-extension operation, closed over the field's encoder.</param>
    /// <param name="state">The pooled precompute to release on disposal, or <see langword="null"/> when the encoder owns nothing.</param>
    /// <exception cref="ArgumentException">When <paramref name="tag"/> is null or empty.</exception>
    /// <exception cref="ArgumentNullException">When <paramref name="interpolate"/> is <see langword="null"/>.</exception>
    public LongfellowRowEncoder(string tag, int dimension, int blockLength, RowInterpolateDelegate interpolate, IDisposable? state = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(tag);
        ArgumentNullException.ThrowIfNull(interpolate);

        Tag = tag;
        Dimension = dimension;
        BlockLength = blockLength;
        this.interpolate = interpolate;
        this.state = state;
    }


    /// <summary>The field label this encoder wraps (diagnostics only).</summary>
    public string Tag { get; }

    /// <summary>The message length <c>N</c>.</summary>
    public int Dimension { get; }

    /// <summary>The codeword length <c>M</c>.</summary>
    public int BlockLength { get; }


    /// <summary>
    /// Extends the <c>N</c> input evaluations in the prefix of <paramref name="evaluations"/> to all
    /// <c>M</c> evaluations in place; the first <c>N</c> are unchanged.
    /// </summary>
    /// <param name="evaluations"><c>M</c> canonical scalars; the first <c>N</c> are the inputs.</param>
    public void Interpolate(Span<byte> evaluations) => interpolate(evaluations);


    /// <summary>Releases the pooled precompute, if any.</summary>
    public void Dispose()
    {
        IDisposable? local = state;
        if(local is not null)
        {
            state = null;
            local.Dispose();
        }
    }


    private string DebuggerDisplayValue => $"{Tag} row encoder (N={Dimension}, M={BlockLength})";
}
