using System.Numerics;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The shape of one small mask code of the hiding WHIR path: a Reed-Solomon
/// zero-knowledge encoding over the scalar field whose codeword carries
/// <c>MessageLength</c> message and <c>RandomnessLength</c> fresh randomness
/// coefficients on the smallest power-of-two domain reaching the requested
/// rate (eprint 2026/391 Definition 3.22 at interleaving width 1). The
/// sumcheck masks of Construction 6.3 and the code-switch masks of
/// Construction 9.7 both live in codes of this shape.
/// </summary>
/// <param name="MessageLength">The message coefficient count.</param>
/// <param name="RandomnessLength">The fresh randomness coefficient count — equal to the mask spot-check budget, so every opened position is simulatable.</param>
/// <param name="DomainSizeLog2">The evaluation-domain exponent.</param>
public readonly record struct WhirMaskCodeShape(
    int MessageLength,
    int RandomnessLength,
    int DomainSizeLog2)
{
    /// <summary>The codeword length <c>2^DomainSizeLog2</c>.</summary>
    public int DomainSize => 1 << DomainSizeLog2;


    /// <summary>
    /// Derives the smallest power-of-two domain carrying the message and
    /// randomness at the requested inverse rate:
    /// <c>2^DomainSizeLog2 = NextPow2(messageLength + randomnessLength) · 2^maskRateLog2</c>.
    /// </summary>
    /// <param name="messageLength">The message coefficient count, positive.</param>
    /// <param name="randomnessLength">The randomness coefficient count, positive.</param>
    /// <param name="maskRateLog2">The mask code's inverse-rate exponent, at least 1.</param>
    /// <returns>The derived shape.</returns>
    public static WhirMaskCodeShape Derive(int messageLength, int randomnessLength, int maskRateLog2)
    {
        int coefficientCount = messageLength + randomnessLength;
        int domainSizeLog2 = BitOperations.Log2(BitOperations.RoundUpToPowerOf2((uint)coefficientCount)) + maskRateLog2;

        return new WhirMaskCodeShape(messageLength, randomnessLength, domainSizeLog2);
    }
}
