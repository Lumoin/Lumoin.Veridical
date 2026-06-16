using System;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Produces a Spartan2 proof of R1CS satisfaction with random-oracle
/// zero-knowledge. The witness is hidden by Hyrax's perfectly-hiding
/// commitment; the sumcheck round polynomials leak
/// <c>O((log m + log n) · degree)</c> field elements that are bounded
/// linear combinations of <c>(Az, Bz, Cz)</c> evaluations at the
/// round's folded boolean hypercube; the protocol's soundness rests on
/// discrete-log hardness over BLS12-381 G1 plus the random-oracle
/// assumption on the Fiat-Shamir transcript. The transcript schedule
/// pins the canonical Spartan2 absorbed-bytes shape so the implementation
/// is interoperable with any conformant prover or verifier at the
/// protocol level (wire format differs — see SPARTAN2.md §8).
/// </summary>
/// <remarks>
/// <para>
/// The prover wraps a <see cref="SpartanProvingKey"/> and is constructed
/// once per (instance, commitment key) pair. <c>Prove</c> is called
/// once per witness; the proving key may be reused across many
/// witnesses for the same instance.
/// </para>
/// <para>
/// See <c>SPARTAN2.md</c> in this folder for the protocol flow,
/// transcript schedule, proof byte layout, and architectural notes.
/// </para>
/// </remarks>
public sealed class SpartanProver: IDisposable
{
    private SpartanProvingKey? provingKey;


    /// <summary>The proving key this prover wraps.</summary>
    public SpartanProvingKey ProvingKey => provingKey ?? throw new ObjectDisposedException(nameof(SpartanProver));

    /// <summary>The curve identifying the scalar field and group operations.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The runtime tag.</summary>
    public Tag Tag { get; }


    /// <summary>
    /// Wraps a proving key in a prover. The prover takes ownership of
    /// the key and disposes it when disposed itself.
    /// </summary>
    /// <param name="provingKey">The proving key. Ownership transfers to this prover.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="provingKey"/> is <see langword="null"/>.</exception>
    public SpartanProver(SpartanProvingKey provingKey)
    {
        ArgumentNullException.ThrowIfNull(provingKey);

        this.provingKey = provingKey;
        Curve = provingKey.Curve;

        Tag = Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.ProvingKey),
            (typeof(CurveParameterSet), (object)provingKey.Curve));
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        provingKey?.Dispose();
        provingKey = null;
    }
}