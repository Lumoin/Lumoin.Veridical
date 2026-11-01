using System;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Tests.TestInfrastructure;

/// <summary>
/// A deterministic byte stream driven by the SplitMix64 generator (Steele, Lea and Flood,
/// "Fast Splittable Pseudorandom Number Generators", OOPSLA 2014). The stream is fully
/// specified here, so a given seed yields the same bytes on every runtime, host and
/// architecture, which <see cref="Random"/> does not promise across runtime versions.
/// </summary>
/// <remarks>
/// Test sweeps that must reproduce a failure from a printed seed use this instead of a
/// property-testing library when the library's type initializers cannot run on the target
/// runtime. Each output word costs a handful of integer operations, and the output quality is
/// far beyond what a differential test needs.
/// </remarks>
internal sealed class SeededByteStream
{
    /// <summary>
    /// The state increment: 2^64 divided by the golden ratio, rounded to an odd integer, so
    /// successive states form a Weyl sequence that visits all 2^64 values before repeating.
    /// </summary>
    private const ulong GoldenGamma = 0x9E3779B97F4A7C15UL;

    /// <summary>The first multiplier of the SplitMix64 output mixer, a finalizer constant of its mixing function.</summary>
    private const ulong FirstMixMultiplier = 0xBF58476D1CE4E5B9UL;

    /// <summary>The second multiplier of the SplitMix64 output mixer, a finalizer constant of its mixing function.</summary>
    private const ulong SecondMixMultiplier = 0x94D049BB133111EBUL;

    /// <summary>The xorshift distance before the first multiplication of the output mixer.</summary>
    private const int FirstMixShift = 30;

    /// <summary>The xorshift distance before the second multiplication of the output mixer.</summary>
    private const int SecondMixShift = 27;

    /// <summary>The closing xorshift distance of the output mixer.</summary>
    private const int FinalMixShift = 31;

    /// <summary>The current SplitMix64 state, advanced by <see cref="GoldenGamma"/> on every output word.</summary>
    private ulong state;


    /// <summary>
    /// Creates a stream positioned at the start of the sequence determined by <paramref name="seed"/>.
    /// </summary>
    /// <param name="seed">The seed; equal seeds produce identical streams.</param>
    public SeededByteStream(ulong seed)
    {
        state = seed;
    }


    /// <summary>
    /// Returns the next 64-bit word of the stream.
    /// </summary>
    /// <returns>The next pseudorandom word.</returns>
    public ulong NextUInt64()
    {
        state += GoldenGamma;
        ulong z = state;
        z = (z ^ (z >> FirstMixShift)) * FirstMixMultiplier;
        z = (z ^ (z >> SecondMixShift)) * SecondMixMultiplier;

        return z ^ (z >> FinalMixShift);
    }


    /// <summary>
    /// Fills <paramref name="destination"/> with the next bytes of the stream. Each word
    /// contributes its bytes in little-endian order, and a final partial word contributes
    /// only the bytes needed, so splitting a fill into several calls at word boundaries
    /// yields the same bytes as one call.
    /// </summary>
    /// <param name="destination">The span to fill.</param>
    public void Fill(Span<byte> destination)
    {
        Span<byte> word = stackalloc byte[sizeof(ulong)];
        int position = 0;
        while(position < destination.Length)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(word, NextUInt64());
            int take = Math.Min(sizeof(ulong), destination.Length - position);
            word[..take].CopyTo(destination.Slice(position, take));
            position += take;
        }
    }


    /// <summary>
    /// Returns an integer drawn from the inclusive range
    /// [<paramref name="minimum"/>, <paramref name="maximum"/>].
    /// </summary>
    /// <param name="minimum">The smallest value that may be returned.</param>
    /// <param name="maximum">The largest value that may be returned; not less than <paramref name="minimum"/>.</param>
    /// <returns>A value in the range. The reduction modulo the range width carries a bias below 2^-31 for the widths used in tests, which does not matter for coverage sampling.</returns>
    public int NextInt(int minimum, int maximum)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maximum, minimum);
        ulong width = (ulong)((long)maximum - minimum) + 1;

        return (int)(minimum + (long)(NextUInt64() % width));
    }
}
