namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// The Keccak-f[1600] round constants, rotation offsets and witness-slicing predicate, a faithful
/// port of google/longfellow-zk's <c>circuits/tests/sha3/sha3_round_constants.{h,cc}</c> and
/// <c>sha3_slicing.h</c> (FIPS 202 sections 3.2.2 and 3.2.5).
/// </summary>
internal static class LongfellowSha3Constants
{
    /// <summary>The permutation's round count.</summary>
    public const int RoundCount = 24;

    /// <summary>The witness-slicing period: the circuit re-anchors the state on witness wires at every sixth round and always at the final one.</summary>
    private const int SlicePeriod = 6;

    /// <summary>The iota round constants (the reference's <c>sha3_rc</c>).</summary>
    public static ulong[] RoundConstants { get; } =
    [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
        0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ];

    /// <summary>The rho rotation offsets in the reference's traversal order (the reference's <c>sha3_rotc</c>).</summary>
    public static int[] RotationCounts { get; } =
    [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
        27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ];


    /// <summary>
    /// The reference's <c>sha3_slice_at</c>: whether the circuit consumes witness wires for the
    /// state after this round — the final round always, and every round whose index is congruent
    /// to five modulo the slicing period (rounds 5, 11, 17 and 23).
    /// </summary>
    /// <param name="round">The round index.</param>
    /// <returns>Whether the round is sliced.</returns>
    public static bool SliceAt(int round)
    {
        return round == RoundCount - 1 || (round % SlicePeriod) == (SlicePeriod - 1);
    }
}
