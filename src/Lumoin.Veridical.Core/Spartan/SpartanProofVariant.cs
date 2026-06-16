namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Discriminates Spartan2 proof variants at the algebraic-identity
/// (tag) level. The variant identifier is what distinguishes a base
/// <see cref="SpartanProof"/> from a <see cref="MaskedSpartanProof"/>
/// and from future ZK-construction sibling proof types per the
/// taxonomy in <c>SPARTAN-ZK-DESIGN.md</c>.
/// </summary>
/// <param name="Identifier">A stable string identifying the variant; the same identifier appears in proof tag entries for runtime discrimination.</param>
/// <remarks>
/// <para>
/// The variant entries cover the full Category A and Category B
/// surface the design document anticipates. <see cref="Unmasked"/>
/// and <see cref="MaskedStatistical"/> are the variants the codebase
/// currently produces and verifies; the other two are reserved
/// for future ZK constructions and exist so the type system carries
/// the full taxonomy from the design doc rather than growing one
/// entry at a time.
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
    /// The statistically-masked Category A construction implemented by
    /// <c>MaskedSpartanProver</c> (SM.7b): degree-matched
    /// sum-of-univariates kernel masks (Libra, Xie et al CRYPTO 2019
    /// §4.1; lineage Chiesa, Forbes, Spooner 2017, IACR ePrint
    /// 2017/305) with the filler-laundered weighted-opening binding of
    /// <c>ZK-STATMASK-DESIGN.md</c> v3. The round messages and
    /// terminating evaluations are statistically masked; the
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
    /// <c>G^k</c> summation decommitment subprotocol). Largely
    /// superseded: the statistical round-message masking it was
    /// reserved for landed as <see cref="MaskedStatistical"/> via the
    /// sum-of-univariates kernel at <c>O(d)</c> mask cost instead of
    /// Construction 6.6's <c>3^d</c>/<c>4^d</c>. Kept so the taxonomy
    /// records the faithful-construction road not taken. Not
    /// implemented.
    /// </summary>
    public static SpartanProofVariant MaskedCfs2017Strong { get; } =
        new("veridical.spartan2.masked-cfs2017-strong");

    /// <summary>
    /// Reserved for a future Hyrax-style commit-and-prove Category A
    /// construction per Setty 2020 §8: send each round message as a
    /// Pedersen commitment plus per-round equality, product, and
    /// knowledge proofs. Requires three new commitment-layer
    /// primitives. Not currently implemented.
    /// </summary>
    public static SpartanProofVariant MaskedHyrax { get; } =
        new("veridical.spartan2.masked-hyrax");
}