namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// Stable Fiat-Shamir operation labels for the BaseFold IOPP. Pinned strings
/// so a prover and verifier in any runtime reproduce identical transcript
/// states — hence identical fold challenges and query indices — from identical
/// inputs.
/// </summary>
/// <remarks>
/// <para>
/// Labels follow the codebase's hierarchical scheme: the first segment names
/// the protocol (<c>basefold.iopp</c>), the rest the message kind. The label
/// is the second line of defence against transcript-confusion attacks; the
/// first is the
/// <see cref="WellKnownBaseFoldIoppParameters.TranscriptDomainLabel"/>
/// separation. No label is a prefix of another that can follow it with
/// different data in the same transcript.
/// </para>
/// </remarks>
public static class WellKnownBaseFoldTranscriptLabels
{
    /// <summary>Label for absorbing a fold-layer codeword's Merkle root (the per-round commitment in the commit phase).</summary>
    public const string FoldRoot = "basefold.iopp.fold.root";

    /// <summary>Label for squeezing a per-round fold challenge <c>α</c>.</summary>
    public const string FoldChallenge = "basefold.iopp.fold.challenge";

    /// <summary>Label for absorbing the final (base-layer) codeword sent in the clear.</summary>
    public const string FinalOracle = "basefold.iopp.final.oracle";

    /// <summary>Label for squeezing a verifier query index in the query phase.</summary>
    public const string QueryIndex = "basefold.iopp.query.index";
}
