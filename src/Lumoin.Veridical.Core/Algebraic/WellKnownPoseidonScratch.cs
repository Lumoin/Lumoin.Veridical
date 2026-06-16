namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Stack-scratch bounds of the Poseidon implementation: the widest supported
/// state (circomlib pins round counts up to <c>t = 17</c>) bounds the
/// <c>stackalloc</c> working buffers so they stay safely on the stack.
/// </summary>
internal static class WellKnownPoseidonScratch
{
    //circomlib's widest pinned state (16 inputs + 1 capacity lane).
    private const int MaximumStateWidth = 17;

    /// <summary>The largest state buffer the permutation stack-allocates.</summary>
    public const int MaximumStateBytes = MaximumStateWidth * Scalar.SizeBytes;
}
