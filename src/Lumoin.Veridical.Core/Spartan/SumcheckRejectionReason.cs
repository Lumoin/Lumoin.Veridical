namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Identifies why a sumcheck verification rejected a proof.
/// </summary>
public enum SumcheckRejectionReason
{
    /// <summary>The default zero value; not emitted by the verifier.</summary>
    None = 0,

    /// <summary>The number of rounds in the proof does not match the expected count derived from the claim.</summary>
    RoundCountMismatch = 1,

    /// <summary>A round polynomial's algebraic degree exceeds the per-round degree bound.</summary>
    DegreeBoundExceeded = 2,

    /// <summary>The terminating evaluation does not satisfy the running-claim identity.</summary>
    FinalEvaluationMismatch = 3,

    /// <summary>A compressed round polynomial could not be decompressed against the running claim — typically because the proof byte layout is malformed.</summary>
    MalformedRoundPolynomial = 4,
}