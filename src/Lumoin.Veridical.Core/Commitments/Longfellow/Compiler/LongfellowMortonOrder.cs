namespace Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;

/// <summary>
/// Morton-order (Z-order) comparison over pairs of wire indices and the power-of-two logarithm,
/// ports of google/longfellow-zk's <c>morton::lt</c>/<c>morton::eq</c> and <c>lg</c>
/// (<c>lib/util/ceildiv.h</c>). The canonicalized quad sorts its corners by the Morton interleave of
/// the two hand indices, so the comparison is part of the emitted circuit's observable structure and
/// must match the reference bit for bit.
/// </summary>
/// <remarks>
/// The reference compares two index pairs by subtracting them in an even/odd bit-plane
/// representation and reading the sign, which equals an unsigned comparison of the interleaved
/// Morton codes. Wire indices here are non-negative 32-bit values, so the two 32-bit halves
/// interleave exactly into one 64-bit code and the plain unsigned comparison is equivalent.
/// </remarks>
internal static class LongfellowMortonOrder
{
    /// <summary>
    /// Compares two index pairs in Morton order: <c>(firstLow, firstHigh) &lt; (secondLow, secondHigh)</c>
    /// where the low index occupies the even bits and the high index the odd bits of the interleaved code.
    /// </summary>
    /// <param name="firstLow">The first pair's even-bit index (<c>h[0]</c>).</param>
    /// <param name="firstHigh">The first pair's odd-bit index (<c>h[1]</c>).</param>
    /// <param name="secondLow">The second pair's even-bit index (<c>h[0]</c>).</param>
    /// <param name="secondHigh">The second pair's odd-bit index (<c>h[1]</c>).</param>
    /// <returns><see langword="true"/> when the first pair precedes the second in Morton order.</returns>
    public static bool Less(int firstLow, int firstHigh, int secondLow, int secondHigh)
    {
        ulong first = Interleave((uint)firstLow, (uint)firstHigh);
        ulong second = Interleave((uint)secondLow, (uint)secondHigh);

        return first < second;
    }


    /// <summary>
    /// The smallest <c>k</c> with <c>2^k ≥ n</c> (<c>lg</c> in the reference); <c>Lg(0) == Lg(1) == 0</c>.
    /// </summary>
    /// <param name="n">The count to take the ceiling logarithm of.</param>
    /// <returns>The ceiling base-two logarithm.</returns>
    public static int Lg(int n)
    {
        int log = 0;
        long power = 1;
        while(power < n)
        {
            power *= 2;
            log++;
        }

        return log;
    }


    /// <summary>
    /// Interleaves two 32-bit values into one 64-bit Morton code, <paramref name="low"/> on the even
    /// bits and <paramref name="high"/> on the odd bits.
    /// </summary>
    /// <param name="low">The even-bit value.</param>
    /// <param name="high">The odd-bit value.</param>
    /// <returns>The interleaved code.</returns>
    private static ulong Interleave(uint low, uint high)
    {
        return Spread(low) | (Spread(high) << 1);
    }


    /// <summary>
    /// Spreads the 32 bits of <paramref name="value"/> onto the even bit positions of a 64-bit word,
    /// the inverse of the reference's <c>morton::even</c> bit packing.
    /// </summary>
    /// <param name="value">The value to spread.</param>
    /// <returns>The spread word.</returns>
    private static ulong Spread(uint value)
    {
        ulong x = value;
        x = (x | (x << 16)) & 0x0000FFFF0000FFFFul;
        x = (x | (x << 8)) & 0x00FF00FF00FF00FFul;
        x = (x | (x << 4)) & 0x0F0F0F0F0F0F0F0Ful;
        x = (x | (x << 2)) & 0x3333333333333333ul;
        x = (x | (x << 1)) & 0x5555555555555555ul;

        return x;
    }
}
