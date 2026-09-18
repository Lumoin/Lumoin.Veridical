namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Discriminates Spartan2 proof variants at the algebraic-identity
/// (tag) level. The variant identifier is what distinguishes a base
/// <see cref="SpartanProof"/> from a <see cref="MaskedSpartanProof"/>
/// and from future ZK-construction sibling proof types per the
/// taxonomy the entries below define.
/// </summary>
/// <param name="Identifier">A stable string identifying the variant; the same identifier appears in proof tag entries for runtime discrimination.</param>
/// <remarks>
/// <para>
/// <see cref="Unmasked"/> and <see cref="MaskedStatistical"/> are the variants the codebase
/// produces and verifies; <see cref="MaskedCfs2017Strong"/> and <see cref="MaskedHyrax"/>
/// are reserved for alternative published ZK-masking constructions, so the type carries the full
/// range of anticipated variants rather than growing one entry at a time.
/// </para>
/// </remarks>
public readonly record struct SpartanProofVariant(string Identifier)
{
    /// <summary>
    /// The base, unmasked Spartan2 proof produced by
    /// <see cref="SpartanProver"/> over a relaxed R1CS instance. Hides
    /// the witness via the Hyrax commitment scheme; the round messages
    /// and terminating evaluations are sent in cleartext. Standard
    /// R1CS is the special case of the relaxed identity with
    /// <c>u = 1</c>, <c>E = 0</c>.
    /// </summary>
    public static SpartanProofVariant Unmasked { get; } =
        new("veridical.spartan2.unmasked");

    /// <summary>
    /// The statistically-masked construction implemented by
    /// <c>MaskedSpartanProver</c>: degree-matched
    /// sum-of-univariates kernel masks (Libra, Xie et al CRYPTO 2019
    /// §4.1; lineage Chiesa, Forbes, Spooner 2017, IACR ePrint
    /// 2017/305) with a filler-laundered weighted-opening binding. The
    /// round messages and terminating evaluations are statistically masked; the
    /// end-to-end ZK flavor follows the commitment scheme — DLOG-rooted
    /// computational over Pedersen/IPA, statistical in the ROM over
    /// the full-ZK BaseFold provider, sound-only over plain BaseFold.
    /// </summary>
    public static SpartanProofVariant MaskedStatistical { get; } =
        new("veridical.spartan2.masked-statistical");

    /// <summary>
    /// Reserved for a faithful implementation of CFS 2017
    /// Construction 6.6 (the <c>(m + k)</c>-variate <c>Z</c> polynomial
    /// plus <c>k</c>-variate <c>A</c> polynomial pair with the
    /// <c>G^k</c> summation decommitment subprotocol), which masks round
    /// messages at <c>3^d</c>/<c>4^d</c> cost. <see cref="MaskedStatistical"/>
    /// achieves the same statistical round-message masking via the
    /// sum-of-univariates kernel at the lower <c>O(d)</c> cost instead, so this
    /// entry stands specifically for the faithful Construction 6.6 approach,
    /// kept for completeness of the taxonomy. Not implemented.
    /// </summary>
    public static SpartanProofVariant MaskedCfs2017Strong { get; } =
        new("veridical.spartan2.masked-cfs2017-strong");

    /// <summary>
    /// Reserved for a Hyrax-style commit-and-prove
    /// construction per Setty 2020 §8: send each round message as a
    /// Pedersen commitment plus per-round equality, product, and
    /// knowledge proofs. Requires three new commitment-layer
    /// primitives. Not currently implemented.
    /// </summary>
    public static SpartanProofVariant MaskedHyrax { get; } =
        new("veridical.spartan2.masked-hyrax");
}