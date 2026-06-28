namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// The regime fixing the Ligero proximity parameter <c>δ</c> — the relative Hamming radius the
/// per-opened-column proximity test is guaranteed to reject within — on the proof-size / assumption-strength
/// curve. A larger <c>δ</c> needs fewer opened columns for a target soundness level.
/// </summary>
public enum LigeroSoundnessRegime
{
    /// <summary>
    /// The unique-decoding radius <c>(1 − ρ)/2</c>: the most conservative, fully elementary bound — a word
    /// within this radius has a unique closest codeword. Needs the most opened columns.
    /// </summary>
    UniqueDecoding,

    /// <summary>
    /// The Johnson list-decoding radius <c>1 − √ρ</c>: provable for Reed-Solomon codes via the proximity-gap
    /// theorem (Ben-Sasson, Carmon, Ishai, Kopparty, Saraf, FOCS 2020), and the conservative default.
    /// </summary>
    ListDecodingJohnson,

    /// <summary>
    /// The conjectured list-decoding-capacity radius <c>1 − ρ</c> — the code's full relative minimum distance:
    /// the smallest opened-column count, but relies on the (widely believed, unproven for the proximity test)
    /// capacity conjecture.
    /// </summary>
    ConjecturedCapacity
}
