using System;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Produces a <see cref="MaskedSpartanProof"/> with the statistically-masked
/// Category A ZK construction (SM.7b): degree-matched sum-of-univariates
/// kernel masks (Libra, Xie et al CRYPTO 2019 §4.1; lineage Chiesa, Forbes,
/// Spooner 2017, IACR ePrint 2017/305) bound by filler-laundered weighted
/// openings per design v3 of <c>ZK-STATMASK-DESIGN.md</c>. The
/// round messages and terminating evaluations are statistically masked;
/// over the Hyrax (Pedersen/IPA) path the end-to-end flavor remains
/// computational zero-knowledge in the random-oracle model rooted in the
/// discrete-log assumption, because the openings are.
/// </summary>
/// <remarks>
/// <para>
/// The masked prover composes additively over the base
/// <see cref="SpartanProver"/>: the base prover's transcript schedule,
/// wire format, and test surface are untouched. The masked variant
/// is its own type with its own proof shape
/// (<see cref="MaskedSpartanProof"/>) and verifier
/// (<c>MaskedSpartanVerifier</c>). The construction's algebra lives
/// in the internal <c>MaskedSpartanAlgorithm</c> driver.
/// </para>
/// <para>
/// See <c>SPARTAN-ZK-DESIGN.md</c> §3.4 and <c>SPARTAN2.md</c> §10 for
/// the construction's protocol flow, transcript schedule extensions,
/// byte layout, and the security claim. The statistical end-to-end
/// flavor (in the ROM) is available by proving over the full-ZK
/// BaseFold provider instead (<c>ProveZkBaseFold</c>).
/// </para>
/// </remarks>
public sealed class MaskedSpartanProver: IDisposable
{
    private SpartanProvingKey? provingKey;


    /// <summary>The proving key this prover wraps.</summary>
    public SpartanProvingKey ProvingKey => provingKey ?? throw new ObjectDisposedException(nameof(MaskedSpartanProver));

    /// <summary>The curve identifying the scalar field and group operations.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The runtime tag.</summary>
    public Tag Tag { get; }


    /// <summary>
    /// Wraps a proving key in a masked prover. The masked prover
    /// shares the base <see cref="SpartanProvingKey"/> shape — same
    /// R1CS instance, same Hyrax commitment key. The key's
    /// <c>VectorLength</c> must be large enough to commit both mask
    /// coefficient vectors as single Pedersen rows (<c>2^ℓ₂</c>
    /// generators each, the policy-resolved mask shape) in addition
    /// to the witness MLE's matrix columns; the check runs at
    /// <c>Prove</c> time.
    /// </summary>
    /// <param name="provingKey">The proving key. Ownership transfers to this prover.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="provingKey"/> is <see langword="null"/>.</exception>
    public MaskedSpartanProver(SpartanProvingKey provingKey)
    {
        ArgumentNullException.ThrowIfNull(provingKey);

        this.provingKey = provingKey;
        Curve = provingKey.Curve;

        Tag = Tag.Create(AlgebraicRole.ProvingKey)
            .With(provingKey.Curve)
            .With(SpartanProofVariant.MaskedStatistical);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        provingKey?.Dispose();
        provingKey = null;
    }
}