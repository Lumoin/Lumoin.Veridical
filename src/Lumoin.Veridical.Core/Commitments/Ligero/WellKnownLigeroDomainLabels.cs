namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// Stable Fiat-Shamir <em>domain</em> labels for the Ligero argument. The
/// domain label is the outermost protocol identifier the transcript is
/// initialised with; it separates Ligero's transcript states from every other
/// protocol's so a challenge collision across protocols is impossible even when
/// their absorb sequences coincide.
/// </summary>
/// <remarks>
/// The version suffix discriminates incompatible wire-format revisions: a
/// change to which messages are absorbed in what order takes a new version tag;
/// a transcript-equivalent refactor does not.
/// </remarks>
public static class WellKnownLigeroDomainLabels
{
    /// <summary>The domain label for v1 of the Veridical Ligero argument.</summary>
    public const string LigeroV1 = "veridical.ligero.v1";
}
