using System;
using System.Numerics;

namespace Lumoin.Veridical.Analysis.StatisticalTests;

/// <summary>
/// Vector-width accumulation for the statistical experiments' histogram
/// pooling: the 256-bin <see cref="long"/> adds are textbook lane-parallel
/// shapes (the recorded SIMD seam from batch AC), and integer addition is
/// exact, so the vectorized pooling is result-identical to the scalar loop.
/// </summary>
internal static class VectorizedAccumulation
{
    /// <summary>
    /// Adds <paramref name="source"/> elementwise into
    /// <paramref name="target"/>: <c>target[i] += source[i]</c>.
    /// </summary>
    /// <param name="target">The accumulator.</param>
    /// <param name="source">The addend; same length as <paramref name="target"/>.</param>
    /// <exception cref="ArgumentException">When the lengths differ.</exception>
    public static void AddInPlace(Span<long> target, ReadOnlySpan<long> source)
    {
        if(target.Length != source.Length)
        {
            throw new ArgumentException($"Accumulator and addend must have equal lengths; received {target.Length} and {source.Length}.", nameof(source));
        }

        int i = 0;
        int width = Vector<long>.Count;
        for(; i <= target.Length - width; i += width)
        {
            var sum = Vector.Add(new Vector<long>(target.Slice(i, width)), new Vector<long>(source.Slice(i, width)));
            sum.CopyTo(target.Slice(i, width));
        }

        for(; i < target.Length; i++)
        {
            target[i] += source[i];
        }
    }
}
