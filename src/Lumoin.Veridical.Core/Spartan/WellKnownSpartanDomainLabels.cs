namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Stable Fiat-Shamir <em>domain</em> labels for the Spartan2 prover
/// and verifier. The domain label is the outermost protocol identifier
/// the transcript is initialised with; changing it makes every
/// transcript state in this protocol's runs distinct from runs of any
/// other protocol.
/// </summary>
/// <remarks>
/// The version suffix discriminates incompatible wire-format revisions.
/// A protocol change that alters which messages are absorbed in what
/// order takes a new version tag; cosmetic refactors that preserve
/// transcript-equivalence do not.
/// </remarks>
public static class WellKnownSpartanDomainLabels
{
    /// <summary>The domain label for v1 of the Veridical Spartan2 protocol.</summary>
    public const string SpartanV1 = "veridical.spartan2.v1";
}