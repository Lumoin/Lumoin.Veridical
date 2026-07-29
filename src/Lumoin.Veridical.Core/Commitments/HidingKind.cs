namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// The hiding character of a proof path's commitment and opening — the privacy
/// axis of a <see cref="SecurityLevelLedger"/>, kept separate from the soundness
/// bits because the two protect against different adversaries (a cheating prover
/// versus a curious verifier).
/// </summary>
public enum HidingKind
{
    /// <summary>
    /// The commitment or opening reveals information about the committed
    /// polynomial beyond the opened evaluation (a deterministic Merkle root over
    /// the codeword, cleartext queried positions). Sound, but not private.
    /// </summary>
    None,

    /// <summary>
    /// Hiding under a computational assumption (Pedersen-family commitments
    /// under discrete log): a computationally bounded verifier learns nothing
    /// beyond the opened evaluation.
    /// </summary>
    Computational,

    /// <summary>
    /// Statistically hiding: the verifier's view is statistically close to a
    /// simulated one (the salted, dimension-lifted ZK BaseFold under its
    /// enforced hiding budget with the statistical sumcheck mask), with no
    /// computational assumption on the verifier.
    /// </summary>
    Statistical
}
